# spamblocker
The SpamBlocker program creates a regexpr list of spam sites and updates the IIS applicationHost.config file with a url rewrite rule.


THE URLREWRITER MODULE MUST BE INSTALLED ON IIS FOR THIS TO WORK

the spamblocker.exe can take 1 argument, which is the url of the list of url sources to build the list with.

e.g.

spamblocker.exe http://params.nevoweb.com/spam-blacklist-sources.txt

If no parameter is passed the a default of "http://params.nevoweb.com/spam-blacklist-sources.txt" will be used.

The url source list should be a simple txt list of sources that spamblocker will use.

e.g.

https://raw.githubusercontent.com/piwik/referrer-spam-blacklist/master/spammers.txt
http://params.nevoweb.com/spam-blacklist.txt


The first of the examples is the piwik github list.

The second is the nevoweb spam sites we have noticed, these 2 lists should be a simple text file, with each line being a spam url.

e.g.

traffic2cash.xyz
site-48089558-1.snip.tw
top1-seo-service.com
quit-smoking.ga
santasgift.ml
build-a-better-business.2your.site
topseoservices.co
trafficgenius.xyz
build-audience.for-your.website
new-look.for-your.website
rusexy.xyz
w3javascript.com
smarter-content.for-your.website
website-stealer-warning.hdmoviecamera.net
 
Each url on the source list will be read and then used to build the regexpr.

 