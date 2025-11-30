#!/usr/bin/perl

print "Content-type: text/html\n";

# SNORTER v2.0

# Author : Jean Philippe Guillemin [ jpgu@users.sourceforge.net ]
# GNU GENERAL PUBLIC LICENSE http://www.gnu.org/copyleft/gpl.html


use CGI;
use DBI;
use strict;


##################################################################################################
# form variables handling


my $CGI=CGI->new();
my $USER=$CGI->param('user');
my $PASS=$CGI->param('pw');
my $HOST=$CGI->param('host');
my $DBNAME=$CGI->param('db');
my $LIMIT=$CGI->param('limit');
my $MINDATE=$CGI->param('mindate');
my $MAXDATE=$CGI->param('maxdate');
my $TRI=$CGI->param('tri');
my $MEMPW=$CGI->param('mempw');
my $TYPE_DEL=$CGI->param('type_del');
my $TARGET_DEL=$CGI->param('target_del');
my $HACKER=$CGI->param('hacker');






my ($BESTOF_QUERY,$SENSORS_QUERY,$TAB_QUERY,$HUMAN_DATE,%class,@hosts);

$class{'icmp-event'} = "low";
$class{'misc-activity'} = "low";
$class{'network-scan'} = "low";
$class{'not-suspicious'} = "low";
$class{'protocol-command-decode'} = "low";
$class{'string-detect'} = "low";
$class{'unknown'} = "low";

$class{'attempted-dos'} = "medium";
$class{'attempted-recon'} = "medium";
$class{'bad-unknown'} = "medium";
$class{'denial-of-service'} = "medium";
$class{'misc-attack'} = "medium";
$class{'non-standard-protocol'} = "medium";
$class{'rpc-portmap-decode'} = "medium";
$class{'successful-dos'} = "medium";
$class{'successful-recon-largescale'} = "medium";
$class{'successful-recon-limited'} = "medium";
$class{'suspicious-filename-detect'} = "medium";
$class{'suspicious-login'} = "medium";
$class{'system-call-detect'} = "medium";
$class{'unusual-client-port-connection'} = "medium";
$class{'web-application-activity'} = "medium";

$class{'attempted-admin'} = "high";
$class{'attempted-user'} = "high";
$class{'shellcode-detect'} = "high";
$class{'successful-admin'} = "high";
$class{'successful-user'} = "high";
$class{'trojan-activity'} = "high";
$class{'unsuccessful-user'} = "high";
$class{'web-application-attack'} = "high";








##################################################################################################
# Main program


if ($TRI eq ""){
	$TRI = 3;
}

$HUMAN_DATE=sapiens(time());
&build_report_query();
&head();
&form();


if ($TYPE_DEL eq "6"){
	&delete_all();
	$TYPE_DEL = "1";
}



if ($TARGET_DEL ne ""){
	
	if ($TYPE_DEL eq "1"){
		&del_by_source();
	}
	
	if ($TYPE_DEL eq "2"){
		&del_by_dest();
	}
	
	if ($TYPE_DEL eq "3"){
		&del_by_date();
	}
	
	if ($TYPE_DEL eq "4"){
		&del_by_signature();
	}
	
	if ($TYPE_DEL eq "5"){
		&del_by_sensor();
	}
}

if ($PASS ne ""){

	&report();
}
&foot();

##################################################################################################
# reporting SQL queries


sub build_report_query {

	if ($TRI eq "1"){
		$TAB_QUERY="
		SELECT event.cid,event.sid,inet_ntoa(iphdr.ip_src),inet_ntoa(iphdr.ip_dst),event.timestamp,sig_class.sig_class_name,signature.sig_sid
		FROM iphdr,event,signature,sig_class
		WHERE inet_ntoa(iphdr.ip_src)=\"$HACKER\" and event.signature=signature.sig_id and iphdr.cid=event.cid and sig_class.sig_class_id=signature.sig_class_id and left(event.timestamp, 10) >= \"$MINDATE\" and left(event.timestamp, 10) <= \"$MAXDATE\"
		ORDER BY iphdr.ip_src;";
	}
	if ($TRI eq "2"){
		$TAB_QUERY="
		SELECT event.cid,event.sid,inet_ntoa(iphdr.ip_src),inet_ntoa(iphdr.ip_dst),event.timestamp,sig_class.sig_class_name,signature.sig_sid
		FROM iphdr,event,signature,sig_class
		WHERE inet_ntoa(iphdr.ip_src)=\"$HACKER\" and event.signature=signature.sig_id and iphdr.cid=event.cid and sig_class.sig_class_id=signature.sig_class_id and left(event.timestamp, 10) >= \"$MINDATE\" and left(event.timestamp, 10) <= \"$MAXDATE\"
		ORDER BY iphdr.ip_dst;";
	}
	if ($TRI eq "3"){
		$TAB_QUERY="
		SELECT event.cid,event.sid,inet_ntoa(iphdr.ip_src),inet_ntoa(iphdr.ip_dst),event.timestamp,sig_class.sig_class_name,signature.sig_sid
		FROM iphdr,event,signature,sig_class
		WHERE inet_ntoa(iphdr.ip_src)=\"$HACKER\" and event.signature=signature.sig_id and iphdr.cid=event.cid and sig_class.sig_class_id=signature.sig_class_id and left(event.timestamp, 10) >= \"$MINDATE\" and left(event.timestamp, 10) <= \"$MAXDATE\"
		ORDER BY event.timestamp DESC;";
	}
	if ($TRI eq "4"){
		$TAB_QUERY="
		SELECT event.cid,event.sid,inet_ntoa(iphdr.ip_src),inet_ntoa(iphdr.ip_dst),event.timestamp,sig_class.sig_class_name,signature.sig_sid
		FROM iphdr,event,signature,sig_class
		WHERE inet_ntoa(iphdr.ip_src)=\"$HACKER\" and event.signature=signature.sig_id and iphdr.cid=event.cid and sig_class.sig_class_id=signature.sig_class_id and left(event.timestamp, 10) >= \"$MINDATE\" and left(event.timestamp, 10) <= \"$MAXDATE\"
		ORDER BY event.signature;";
	}
	if ($TRI eq "5"){
		$TAB_QUERY="
		SELECT event.cid,event.sid,inet_ntoa(iphdr.ip_src),inet_ntoa(iphdr.ip_dst),event.timestamp,sig_class.sig_class_name,signature.sig_sid
		FROM iphdr,event,signature,sig_class
		WHERE inet_ntoa(iphdr.ip_src)=\"$HACKER\" and event.signature=signature.sig_id and iphdr.cid=event.cid and sig_class.sig_class_id=signature.sig_class_id and left(event.timestamp, 10) >= \"$MINDATE\" and left(event.timestamp, 10) <= \"$MAXDATE\"
		ORDER BY event.sid;";
	}
	# like \'\%$query\%\';";
}

##################################################################################################
#   Report

sub report{	
	my ($i,
		$DBH,
		$STH,
		$NUMBEROW,
		$NUMBERFIELDS,
		@COLUMN,
		$REF,
		$tr,
		$SIGID,
		$event_class);
	
	
	$DBH = DBI->connect("DBI:mysql:$DBNAME:$HOST","$USER","$PASS");
	
	
	# <A HREF=\"header.pl\?db=snort\&user=snort\&host=192.168.1.200\&pw=snortpw\&cid=".$$REF[$i]."\&sid=".$$REF[$i+1]."\" >$$REF[$i]</a>	
	$STH = $DBH->prepare($TAB_QUERY); # sending query to mysql
	$STH->execute();
	$NUMBEROW = $STH->rows;
	print "<H3>$NUMBEROW Alerts(s) from $MINDATE to $MAXDATE :</H3>\n"; # debug
	$NUMBERFIELDS = $STH->{'NUM_OF_FIELDS'};	# number of fields in the result table
	# $COLUMNAME = $STH->{'NAME'};
	@COLUMN=("ALERT ANALYSIS","SENSOR","SOURCE IP\@","DEST IP\@","DATE","SIGNATURE","SID","THREAT");

	# printing the result TAB
	print "
	<CENTER>\n
	<TABLE BORDER=0 CELLPADDING=5 bgcolor=\"#aeaaae\" width=\"100\%\">\n
	<TR bgcolor=\"#00008b\">";
	for ($i = 0;  $i < 8;  $i++) {
	     print "
	     <TD ALIGN=center><B><FONT size=\"1\" color=\"#ffffff\">@COLUMN[$i]</FONT></B></TD>";
	}
	print "</TR>\n";
	$tr=0;
	while ($REF = $STH->fetchrow_arrayref) {
		$tr++;
		if ($tr % 2) {
			print "<TR bgcolor=\"#cccccc\">";
		}else{
			print "<TR bgcolor=\"#bbbbbb\">";		
		}	
		
		for ($i = 0;  $i < 1;  $i++) {
			print "
			<TD ALIGN=center><FONT size=\"1\">
			<FORM ACTION=\"header.pl\" METHOD= post > \n
			<INPUT TYPE=\"hidden\" NAME=\"pw\" VALUE=".$PASS.">\n
			<INPUT TYPE=\"hidden\" NAME=\"host\" VALUE=".$HOST.">\n
			<INPUT TYPE=\"hidden\" NAME=\"db\" VALUE=".$DBNAME.">\n
			<INPUT TYPE=\"hidden\" NAME=\"user\" VALUE=".$USER.">\n
			<INPUT TYPE=\"hidden\" NAME=\"cid\" VALUE=".$$REF[$i].">\n
			<INPUT TYPE=\"hidden\" NAME=\"sid\" VALUE=".$$REF[$i+1].">\n
			<INPUT TYPE=\"submit\" NAME=\"submitButtonName\" VALUE=\"Details\">\n
			</FORM></FONT></TD>";
		}
		for ($i = 1;  $i < 2;  $i++) {
			print "
			<TD><CENTER><FONT size=\"1\">$$REF[$i]</FONT></CENTER></TD>";
		}		
		for ($i = 2;  $i < 4;  $i++) {
			print "
			<TD><FONT size=\"1\">$$REF[$i]</FONT></TD>";
		}
		for ($i = 4;  $i < 5;  $i++) {
			print "
			<TD><FONT size=\"1\">$$REF[$i]</FONT></TD>";
		}
		for ($i = 5;  $i < 6;  $i++) {
			print "
			<TD><FONT size=\"1\">$$REF[$i]</FONT></TD>";
			$event_class=$$REF[$i];
		}
		for ($i = 6;  $i < 7;  $i++) {
			print "
			<TD><FONT size=\"1\">$$REF[$i]</FONT></TD>";
			$SIGID=$$REF[$i];
		}
		if ($class{$event_class} eq "low"){
			print "
			<TD ALIGN=center><A HREF=\"http://www.snort.org/snort-db/sid.html?sid=".$SIGID."\" TARGET=new>
			<IMG BORDER=0 width=22 height=22 SRC=\"./safe.gif\" ALT=\"Whois\"></A></TD>";
		}
		elsif ($class{$event_class} eq "medium"){
			print "
			<TD ALIGN=center><A HREF=\"http://www.snort.org/snort-db/sid.html?sid=".$SIGID."\" TARGET=new>
			<IMG BORDER=0 width=22 height=22 SRC=\"./medium.gif\" ALT=\"Whois\"></A></TD>";
		}
		elsif ($class{$event_class} eq "high"){
			print "
			<TD ALIGN=center><A HREF=\"http://www.snort.org/snort-db/sid.html?sid=".$SIGID."\" TARGET=new>
			<IMG BORDER=0 width=22 height=22 SRC=\"./critical.gif\" ALT=\"Whois\"></A></TD>";
		}
		else{
			print "
			<TD ALIGN=center><A HREF=\"http://www.snort.org/snort-db/sid.html?sid=".$SIGID."\" TARGET=new>
			<IMG BORDER=0 width=22 height=22 SRC=\"./unknown.gif\" ALT=\"Whois\"></A></TD>";
		}
		print "</TR>\n";
	}
	print "
	</TABLE></CENTER>\n";
	#print "<P><B>sql :  </B>".$TAB_QUERY."</p>\n";	 # debug
	$STH->finish();
	$DBH->disconnect();
}

##################################################################################################
# Delete by destination


sub del_by_dest {
	my (@TABLES,
		$STH,
		$DBH,
		$REF,
		$DEL_QUERY,
		$i,
		$j,
		$DELETE_REQUEST,
		@SID,
		@CID);
	

	# Searching for common CID	#

	$DEL_QUERY="
		SELECT iphdr.cid
		FROM iphdr
		WHERE iphdr.ip_dst = inet_aton(\"$TARGET_DEL\") and iphdr.ip_src = inet_aton(\"$HACKER\");";
	
	$DBH = DBI->connect("DBI:mysql:$DBNAME:$HOST","$USER","$PASS");

	$STH = $DBH->prepare($DEL_QUERY); # sending query to MYSQL
	$STH->execute();
	while ($REF = $STH->fetchrow_arrayref) {
		push(@CID,$$REF[$i]);
	}

	# Deleting	events #

	@TABLES = ('event','iphdr','icmphdr','tcphdr','udphdr','opt','data');
	for ($j = 0;  $j < $#CID+1;  $j++) {
		for ($i = 0;  $i < $#TABLES+1;	$i++) {
			$DELETE_REQUEST="DELETE FROM @TABLES[$i] WHERE @TABLES[$i].cid = \"@CID[$j]\";";
			$STH = $DBH->prepare($DELETE_REQUEST);
			$STH->execute();
		}
	}
	$STH->finish();
	$DBH->disconnect();
}

##################################################################################################
# Delete by date

sub del_by_date {
	my (@TABLES,
		$STH,
		$DBH,
		$REF,
		$DEL_QUERY,
		$i,
		$j,
		$DELETE_REQUEST,
		@SID,
		@CID);
	

	# Searching for common CID	#

	$DEL_QUERY="
		SELECT event.cid
		FROM event
		WHERE event.timestamp = \"$TARGET_DEL\" and iphdr.ip_src = inet_aton(\"$HACKER\");";
	
	$DBH = DBI->connect("DBI:mysql:$DBNAME:$HOST","$USER","$PASS");

	$STH = $DBH->prepare($DEL_QUERY); # sending query to MYSQL
	$STH->execute();
	while ($REF = $STH->fetchrow_arrayref) {
		push(@CID,$$REF[$i]);
	}

	
	# Deleting	events #

	@TABLES = ('event','iphdr','icmphdr','tcphdr','udphdr','opt','data');
	for ($j = 0;  $j < $#CID+1;  $j++) {
		for ($i = 0;  $i < $#TABLES+1;	$i++) {
			$DELETE_REQUEST="DELETE FROM @TABLES[$i] WHERE @TABLES[$i].cid = \"@CID[$j]\";";
			$STH = $DBH->prepare($DELETE_REQUEST);
			$STH->execute();
		}
	}
	$STH->finish();
	$DBH->disconnect();
}


##################################################################################################
# Delete by signature


sub del_by_signature {
	my (@TABLES,
		$STH,
		$DBH,
		$REF,
		$DEL_QUERY,
		$i,
		$j,
		$DELETE_REQUEST,
		@SID,
		@CID);
	

	# Searching for common CID	#

	$DEL_QUERY="
		SELECT event.cid 
		FROM event
		WHERE event.signature = \"$TARGET_DEL\" and iphdr.ip_src = inet_aton(\"$HACKER\");";
	
	$DBH = DBI->connect("DBI:mysql:$DBNAME:$HOST","$USER","$PASS");

	$STH = $DBH->prepare($DEL_QUERY); # sending query to MYSQL
	$STH->execute();
	while ($REF = $STH->fetchrow_arrayref) {
		push(@CID,$$REF[$i]);
	}

	# Deleting	events #

	@TABLES = ('event','iphdr','icmphdr','tcphdr','udphdr','opt','data');
	for ($j = 0;  $j < $#CID+1;  $j++) {
		for ($i = 0;  $i < $#TABLES+1;	$i++) {
			$DELETE_REQUEST="DELETE FROM @TABLES[$i] WHERE @TABLES[$i].cid = \"@CID[$j]\";";
			$STH = $DBH->prepare($DELETE_REQUEST);
			$STH->execute();
		}
	}
	
	# Deleting	signatures #

	$DELETE_REQUEST="DELETE FROM signature WHERE signature.sig_sid = \"$TARGET_DEL\";";
	$STH = $DBH->prepare($DELETE_REQUEST);
	$STH->execute();

	$STH->finish();
	$DBH->disconnect();
}

##################################################################################################
# Delete by SENSOR


sub del_by_sensor {
	my (@TABLES,
		$STH,
		$DBH,
		$REF,
		$DEL_QUERY,
		$i,
		$j,
		$DELETE_REQUEST,
		@SID,
		@CID);
	

	# Searching for common CID	#

	$DEL_QUERY="
		SELECT event.cid 
		FROM event 
		WHERE event.sid = \"$TARGET_DEL\" and iphdr.ip_src = inet_aton(\"$HACKER\");";
	
	$DBH = DBI->connect("DBI:mysql:$DBNAME:$HOST","$USER","$PASS");

	$STH = $DBH->prepare($DEL_QUERY); # sending query to MYSQL
	$STH->execute();
	while ($REF = $STH->fetchrow_arrayref) {
		push(@CID,$$REF[$i]);
	}
			
	# Deleting	events	#


	@TABLES = ('event','iphdr','icmphdr','tcphdr','udphdr','opt','data');
	for ($j = 0;  $j < $#CID+1;  $j++) {
		for ($i = 0;  $i < $#TABLES+1;	$i++) {
			$DELETE_REQUEST="DELETE FROM @TABLES[$i] WHERE @TABLES[$i].cid = \"@CID[$j]\";";
			$STH = $DBH->prepare($DELETE_REQUEST);
			$STH->execute();
		}
	}
	
	
	# Deleting	sensors	#



	$DELETE_REQUEST="DELETE FROM sensor WHERE sensor.sid = \"$TARGET_DEL\";";
	$STH = $DBH->prepare($DELETE_REQUEST);
	$STH->execute();

	$STH->finish();
	$DBH->disconnect();
}

##################################################################################################
# Delete all 

sub delete_all {
	my (@TABLES,
		$STH,
		$DBH,
		$REF,
		$DEL_QUERY,
		$i,
		$j,
		$DELETE_REQUEST,
		@SID,
		@CID);
 
	# Searching for common CID	#

	$DEL_QUERY="
		SELECT iphdr.cid
		FROM iphdr
		WHERE iphdr.ip_src = inet_aton(\"$HACKER\");";
	
	$DBH = DBI->connect("DBI:mysql:$DBNAME:$HOST","$USER","$PASS");

	$STH = $DBH->prepare($DEL_QUERY); # sending query to MYSQL
	$STH->execute();
	while ($REF = $STH->fetchrow_arrayref) {
		push(@CID,$$REF[$i]);
	}


	# Deleting events	#


	@TABLES = ('event','iphdr','icmphdr','tcphdr','udphdr','opt','data');
	for ($j = 0;  $j < $#CID+1;  $j++) {
		for ($i = 0;  $i < $#TABLES+1;	$i++) {
			$DELETE_REQUEST="DELETE FROM @TABLES[$i] WHERE @TABLES[$i].cid = \"@CID[$j]\";";
			$STH = $DBH->prepare($DELETE_REQUEST);
			$STH->execute();
		}
	}
	$STH->finish();
	$DBH->disconnect();
}


##################################################################################################
# FORM       

sub form {
	print "
	<TABLE BORDER=0 CELLPADDING=6 bgcolor=\"#00008b\" width=\"100\%\" ><TR> \n
	<TD ALIGN=center><B><FONT color=\"#339966\">REPORT GENERATED on $HUMAN_DATE </FONT></B></TD>
	<TD ALIGN=center><B><FONT color=\"#ffffff\"></FONT></B></TD> \n
	</TR></TABLE>\n

	<FORM ACTION=\"alerts.pl\" METHOD= post > \n
	<INPUT TYPE=\"hidden\" NAME=\"pw\" VALUE=".$PASS.">\n
	<INPUT TYPE=\"hidden\" NAME=\"host\" VALUE=".$HOST.">\n
	<INPUT TYPE=\"hidden\" NAME=\"db\" VALUE=".$DBNAME.">\n
	<INPUT TYPE=\"hidden\" NAME=\"user\" VALUE=".$USER.">\n
	<INPUT TYPE=\"hidden\" NAME=\"mempw\" VALUE=".$MEMPW.">\n
	<INPUT TYPE=\"hidden\" NAME=\"hacker\" VALUE=".$HACKER.">\n
	<INPUT TYPE=\"hidden\" NAME=\"limit\" VALUE=".$LIMIT.">\n
	<INPUT TYPE=\"hidden\" NAME=\"mindate\" VALUE=".$MINDATE.">\n
	<INPUT TYPE=\"hidden\" NAME=\"maxdate\" VALUE=".$MAXDATE.">\n	
	<P><H3>Query options :</H3></P>\n
	<TABLE BORDER=0 CELLPADDING=6 bgcolor=\"#00008b\" width=\"100\%\" ><TR> \n
	<TD ALIGN=center><B><FONT color=\"#ffffff\">SORT ALERTS BY :</FONT></B></TD>
	<TD ALIGN=center><B><FONT color=\"#ffffff\">DELETE FROM DB BY :</FONT></B></TD> \n
	<TD ALIGN=center rowspan=2> \n
	<P><INPUT TYPE=\"submit\" NAME=\"submitButtonName\" VALUE=\"Send query\"> \n
    	<INPUT TYPE=\"reset\" VALUE=\"Reset\"></P> \n
    	</TD></TR>\n
	<TR>\n
	<TD> \n
	<CENTER><SELECT NAME=\"tri\"> \n";
#   	if ($TRI eq "1"){
#		print "<OPTION VALUE=\"1\" SELECTED>Source \n";
#	}else{
#		print "<OPTION VALUE=\"1\">Source \n";
#	}
    	if ($TRI eq "2"){
		print "<OPTION VALUE=\"2\" SELECTED>Destination \n";
	}else{
		print "<OPTION VALUE=\"2\">Destination \n";
	}
	if (($TRI eq "3") || ($TRI eq "")){
		print "<OPTION VALUE=\"3\" SELECTED>Date \n";
	}else{
		print "<OPTION VALUE=\"3\">Date \n";
	}
	if ($TRI eq "4"){
		print "<OPTION VALUE=\"4\" SELECTED>Signature \n";
	}else{
		print "<OPTION VALUE=\"4\">Signature \n";
	}
	if ($TRI eq "5"){
		print "<OPTION VALUE=\"5\" SELECTED>Sensor \n";
	}else{
		print "<OPTION VALUE=\"5\">Sensor \n";
	}
	print "
    	</SELECT></CENTER> \n
	</TD> \n
    <TD> \n
	<CENTER><SELECT NAME=\"type_del\"> \n";
#    	if (($TYPE_DEL eq "1") || ($TRI eq "")){
#		print "<OPTION VALUE=\"1\" SELECTED>Source \n";
#	}else{
#		print "<OPTION VALUE=\"1\">Source \n";
#	}
	if ($TYPE_DEL eq "2"){
		print "<OPTION VALUE=\"2\" SELECTED>Destination \n";
	}else{
		print "<OPTION VALUE=\"2\">Destination \n";
	}
	if ($TYPE_DEL eq "3"){
		print "<OPTION VALUE=\"3\" SELECTED>Date \n";
	}else{
		print "<OPTION VALUE=\"3\">Date \n";
	}
	if ($TYPE_DEL eq "4"){
		print "<OPTION VALUE=\"4\" SELECTED>Signature(ID) \n";
	}else{
		print "<OPTION VALUE=\"4\">Signature(ID) \n";
	}
	if ($TYPE_DEL eq "5"){
		print "<OPTION VALUE=\"5\" SELECTED>Sensor(ID) \n";
	}else{
		print "<OPTION VALUE=\"5\">Sensor(ID) \n";
	}
	print "<OPTION VALUE=\"6\">All(\! \! \!) \n";
	print "
    	</SELECT><FONT color=\"#ffffff\"> = \n</FONT>
	<INPUT TYPE=\"text\" NAME=\"target_del\" size=\"24\"></CENTER>
    </TD></TR></TABLE> \n
    </FORM> \n
    <BR> \n";
}

##################################################################################################
# Header


sub head{
	print "
	<HTML><HEAD>\n
	<BODY lang=FR bgcolor=\"#f4f4e0\" style='FONT-size:08.0pt\;FONT-family:Sans'> \n
	<TABLE ALIGN=center BORDER=0 CELLPADDING=6 bgcolor=\"#f4f4e0\" width=\"100\%\" ><TR> \n
    	<TD><CENTER><A HREF=\"http://www.ripe.net/\" TARGET=new>
    	<IMG BORDER=0 width=50 height=22 SRC=\"./ripe.gif\" ALT=\"Whois\"></A></CENTER></TD> \n
   	<TD><CENTER><A HREF=\"http://www.nic.fr/zonecheck/\" TARGET=new>
	<IMG BORDER=0 width=50 height=22 SRC=\"./afnic.gif\" ALT=\"Zonecheck\"></A></CENTER></TD> \n
   	<TD><CENTER><A HREF=\"http://www.snort.org/snort-db/\" TARGET=new>
	<IMG BORDER=0 width=50 height=22 SRC=\"./snort.gif\" ALT=\"SnortDB\"></A></CENTER></TD> \n
	<TD><CENTER><A HREF=\"http://online.securityfocus.com/bid/\" TARGET=new>
	<IMG BORDER=0 width=50 height=22 SRC=\"./focus.gif\" ALT=\"SecurityFocus\"></A></CENTER></TD> \n
   	</TR></TABLE> \n
	<TITLE>SNORTER</TITLE>\n
	<A name=top></A> \n
	<H1 ALIGN=center>SNORTER</H1> \n
	</HEAD> \n
	<P ALIGN=center>Reporting and investigation for the SNORT Network Intrusion Detection System.</P> \n";
}


##################################################################################################
# Footer


sub foot{
	print "
	<P ALIGN=center>Support : <A HREF=\"mailto:jpgu\@users.sourceforge.net\">jpgu\@users.sourceforge.net</a><BR>\n
	<A HREF=\"http://shweps.free.fr/snorter.html\">http://shweps.free.fr</a><BR>\n
	Report created on : $HUMAN_DATE </P> \n
	<P ALIGN=center><A HREF=\"\#top\">Top of the page</a></P> \n
	</BODY></HTML>";
}


##################################################################################################
# date formating


sub sapiens {
	my ($HUMAN_DATE,$SEC,$MIN,$HOUR,$MDAY,$MONTH,$YEAR,$SDAY,$ADAY,$ISDST);
	($SEC,$MIN,$HOUR,$MDAY,$MONTH,$YEAR,$SDAY,$ADAY,$ISDST) = localtime($_[0]);
	$YEAR = ($YEAR-100);
	$YEAR ="200$YEAR";
	$MONTH++;
	if ($MONTH < 10){
		$MONTH="0".$MONTH;
	}
	if ($MDAY < 10){
		$MDAY="0".$MDAY;
	}
	if ($HOUR < 10){
		$HOUR="0".$HOUR;
	}
	if ($MIN < 10){
		$MIN="0".$MIN;
	}
	if ($SEC < 10){
		$SEC="0".$SEC;
	}
	#@LIST = ('jan','feb','mar','apr','may','jun','jul','aug','sep','oct','nov','dec');
	#$MONTH = $LIST[$MONTH];
	$HUMAN_DATE = "$YEAR-$MONTH-$MDAY $HOUR:$MIN:$SEC ";
return $HUMAN_DATE
}

