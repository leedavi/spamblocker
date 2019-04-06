using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Mail;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

namespace spamblocker
{
    class Program
    {
        private static void Main(string[] args)
        {
            var urllist = "";

            var sourceslist = "https://raw.githubusercontent.com/nbrightproject/spamsafelists/master/spam-blacklist-sources.txt";            
            if (args.Length == 1) sourceslist = args[0];

            // get the source list into an array 
            var sourceslists = GetUrlListFromHttp(sourceslist);
            var slists = sourceslists.Split(Environment.NewLine.ToCharArray());

            // loop on each source and add to the list.
            foreach (var source in slists)
            {
                if (source.ToLower().StartsWith("http"))
                {
                    urllist += GetUrlListFromHttp(source);
                    urllist += Environment.NewLine;
                }
            }


            urllist = urllist.Trim();

            // print out page source
            var lines = urllist.Split(Environment.NewLine.ToCharArray());
            StringBuilder sbWrite = new StringBuilder();
            sbWrite.Append("<rule name=\"Spam-Referrals\">" + Environment.NewLine);
            sbWrite.Append("<match url=\".*\" />" + Environment.NewLine);
            sbWrite.Append("<conditions>" + Environment.NewLine);
            sbWrite.Append("<add input=\"{HTTP_REFERER}\" matchType=\"Pattern\"  pattern=\"");
            var regx = "(^http://)(";
            foreach (var line in lines)
            {
                if (line.Trim() != "")
                {
                    string sOut = Encoding.UTF8.GetString(Encoding.UTF8.GetBytes(line));
                    if (!sOut.Contains("?") && sOut.Trim(' ') != "") // remove any invalid chars lines
                    {
                        if (!regx.Contains(sOut.Replace(".", "\\.")))
                        {
                            regx += ".*" + sOut.Replace(".", "\\.") + "|";
                        }
                    }
                }
            }
            regx = regx.TrimEnd('|') + ")";
            sbWrite.Append(regx + "\" ignoreCase=\"true\" negate=\"false\" />" + Environment.NewLine);
            sbWrite.Append("</conditions>" + Environment.NewLine);
            sbWrite.Append("<action type=\"CustomResponse\" statusCode=\"403\" statusReason=\"Forbidden: Access is denied.\" statusDescription=\"You do not have permission to view this directory or page.\" />" + Environment.NewLine);
            sbWrite.Append("</rule>" + Environment.NewLine);

            // check for changes
            if (File.Exists(".\\spammerblock_regexpr.txt"))
            {
                var oldregx = File.ReadAllText(".\\spammerblock_regexpr.txt");
                if (oldregx != regx)
                {
                    File.WriteAllText(".\\spammerblock_regexpr.txt", regx);
                    File.WriteAllText(".\\spammerblock_xmlnode.txt", sbWrite.ToString());
                    UpdateIIS(sbWrite.ToString());
                }
            }
            else
            {
                File.WriteAllText(".\\spammerblock_regexpr.txt", regx);
                File.WriteAllText(".\\spammerblock_xmlnode.txt", sbWrite.ToString());
                UpdateIIS(sbWrite.ToString());
            }

        }

        private static String GetUrlListFromHttp(String fullurl)
        {
            try
            {

                StringBuilder sb = new StringBuilder();

                // used on each read operation
                Char[] read = new Char[256];

                // prepare the web page we will be asking for
                HttpWebRequest request = (HttpWebRequest) WebRequest.Create(fullurl);

                // execute the request
                HttpWebResponse response = (HttpWebResponse) request.GetResponse();

                // we will read data via the response stream
                Stream resStream = response.GetResponseStream();

                if (resStream != null)
                {
                    Encoding encode = System.Text.Encoding.GetEncoding("utf-8");
                    StreamReader readStream = new StreamReader(resStream, encode);

                    string tempString = null;
                    int count = 0;

                    do
                    {
                        // fill the buffer with data
                        count = readStream.Read(read, 0, 256);
                        // make sure we read some data
                        if (count != 0)
                        {
                            tempString = new String(read, 0, count);

                            // continue building the string
                            sb.Append(tempString);
                        }
                    } while (count > 0); // any more data to read?
                }

                return sb.ToString();
            }
            catch (Exception)
            {
                return "";
            }
        }

        private static void UpdateIIS(String rewriteXmlNode)
        {
            if (rewriteXmlNode != "")
            {
                var hostconfigpath = "C:\\Windows\\System32\\inetsrv\\config\\applicationHost.config";
                if (File.Exists(hostconfigpath))
                {
                    try
                    {
                        var xmlDoc = new XmlDataDocument();
                        xmlDoc.Load(hostconfigpath);

                        // create a global element which will be injected 
                        XmlNode newRuleOuter = xmlDoc.CreateNode(XmlNodeType.Element, "newRule", null);
                        newRuleOuter.InnerXml = rewriteXmlNode;
                        XmlNode newRule = newRuleOuter.SelectSingleNode("rule");


                        var globalRulesNode = xmlDoc.SelectSingleNode("configuration/system.webServer/rewrite/globalRules");
                        if (globalRulesNode == null)
                        {
                            var rewriteNode = xmlDoc.SelectSingleNode("configuration/system.webServer/rewrite");
                            if (rewriteNode == null)
                            {
                                var webServerNod = xmlDoc.SelectSingleNode("configuration/system.webServer");
                                XmlNode rewriteRules = xmlDoc.CreateNode(XmlNodeType.Element, "rewrite", null);
                                webServerNod?.AppendChild(rewriteRules);
                                rewriteNode = xmlDoc.SelectSingleNode("configuration/system.webServer/rewrite");
                            }

                            // create globalrules node and inject rule node/
                            XmlNode newglobalRules = xmlDoc.CreateNode(XmlNodeType.Element, "globalRules", null);
                            newglobalRules.InnerXml = rewriteXmlNode;
                            rewriteNode?.AppendChild(newglobalRules);
                        }
                        else
                        {
                            // rules exists, find name="Spam-Referrals" and replace, if diff
                            XmlNode newruleNode = xmlDoc.CreateNode(XmlNodeType.Element, "rule", null);
                            XmlAttribute nameatt = xmlDoc.CreateAttribute("name");
                            nameatt.Value = "Spam-Referrals";
                            newruleNode.Attributes.Append(nameatt);
                            var innerXml = rewriteXmlNode.Replace("<rule name=\"Spam-Referrals\">", "").Replace("</rule>", "").Trim() + "\r\n";
                            newruleNode.InnerXml = innerXml;
                            var ruleNode = xmlDoc.SelectSingleNode("configuration/system.webServer/rewrite/globalRules/rule[@name='Spam-Referrals']");
                            if (ruleNode == null)
                            {
                                globalRulesNode.AppendChild(newruleNode);
                            }
                            else
                            {
                                globalRulesNode.ReplaceChild(newruleNode, ruleNode);
                            }
                        }
                        xmlDoc.Save(".\\spammerblock_config.xml");

                        // now we've created it overwrite live config file
                        File.Copy("C:\\Windows\\System32\\inetsrv\\config\\applicationHost.config", "C:\\Windows\\System32\\inetsrv\\config\\applicationHost.copy", true);
                        File.Copy(".\\spammerblock_config.xml", "C:\\Windows\\System32\\inetsrv\\config\\applicationHost.config", true);

                    }
                    catch (Exception e)
                    {
                        File.WriteAllText(".\\spammerblock_ERROR.txt", e.Message);
                    }
                }
            }

        }
    }
}
