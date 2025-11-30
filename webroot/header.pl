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
my $CID=$CGI->param('cid');
my $SID=$CGI->param('sid');
my $USER=$CGI->param('user');
my $PASS=$CGI->param('pw');
my $HOST=$CGI->param('host');
my $DBNAME=$CGI->param('db');

my ($HUMAN_DATE,$TYPENUMBER);


##################################################################################################
# Main program


&head();
$HUMAN_DATE=sapiens(time());
&report();
&foot();



sub report{
		my ($i,
			$DBH,
			$STH,
			$NUMBEROW,
			$NUMBERFIELDS,
			@COLUMN,
			$REF,
			$PROTOCOL,
			$SERVICE,
			$ICMPTYPE,
			$ICMPCODE,
			$SIGID);

my $ALERT_QUERY="
SELECT event.timestamp,signature.sig_name,signature.sig_sid,sig_class.sig_class_name
FROM event,signature,sig_class
WHERE event.cid=\"$CID\" and event.sid=\"$SID\" and event.signature=signature.sig_id and sig_class.sig_class_id=signature.sig_class_id;";

my $IPHEADER_QUERY="
SELECT inet_ntoa(iphdr.ip_src),inet_ntoa(iphdr.ip_dst),iphdr.ip_len,iphdr.ip_ttl,iphdr.ip_proto 
FROM iphdr
WHERE iphdr.cid=\"$CID\" and iphdr.sid=\"$SID\" ;";

my $TCPHEADER_QUERY="
SELECT tcphdr.tcp_sport,tcphdr.tcp_dport,tcphdr.tcp_win,tcphdr.tcp_flags,tcphdr.tcp_seq 
FROM tcphdr
WHERE tcphdr.cid=\"$CID\" and tcphdr.sid=\"$SID\" ;";

my $UDPHEADER_QUERY="
SELECT udphdr.udp_sport,udphdr.udp_dport
FROM udphdr
WHERE udphdr.cid=\"$CID\" and udphdr.sid=\"$SID\" ;";
	
my $ICMPHEADER_QUERY="
SELECT icmphdr.icmp_type,icmphdr.icmp_code,icmp_id
FROM icmphdr
WHERE icmphdr.cid=\"$CID\" and icmphdr.sid=\"$SID\" ;";


	
##################################################################################################
# Report


	
	$DBH = DBI->connect("DBI:mysql:$DBNAME:$HOST","$USER","$PASS");
	
	print "<H3>Alert detail for event $CID from sensor $SID :</H3>\n"; # debug
	$STH = $DBH->prepare($ALERT_QUERY); # sending query to mysql
	$STH->execute();
	@COLUMN=("DATE","SIGNATURE","SID","CLASS","INFO");

	# printing the result TAB
	print "
	<CENTER>
	<TABLE BORDER=0 CELLPADDING=5 bgcolor=\"#aeaaae\" width=\"100\%\">
	<TR bgcolor=\"#00008b\">";
	for ($i = 0;  $i < 5;  $i++) {
	     print "
	     <TD ALIGN=center><B><FONT size=\"1\" color=\"#ffffff\">@COLUMN[$i]</FONT></B></TD>";
	}
	print "</TR>\n";
	while ($REF = $STH->fetchrow_arrayref) {
		print "<TR bgcolor=\"#cccccc\">";
		for ($i = 0;  $i < 4;  $i++) {
			print "
			<TD><CENTER><FONT size=\"1\">$$REF[$i]</FONT></CENTER></TD>";
		}		
		$SIGID=$$REF[$i-2];
		print "
		<TD ALIGN=center><A HREF=\"http://www.snort.org/snort-db/sid.html?sid=".$SIGID."\" TARGET=new>
		<IMG BORDER=0 width=50 height=22 SRC=\"./snort.gif\" ALT=\"Whois\"></A></TD>";

		print "</TR></TABLE></CENTER>\n";
	}




##################################################################################################
# IP layer               


	$STH = $DBH->prepare($IPHEADER_QUERY); # sending query to mysql
	$STH->execute();
	$NUMBEROW = $STH->rows;
	print "<H4>IP header details</H4>\n";
	@COLUMN=("SRC IP","DST IP","LEN","IP TTL","PROTO");

	# printing the result TAB
	
	print "
	<CENTER>
	<TABLE BORDER=0 CELLPADDING=5 bgcolor=\"#aeaaae\" width=\"100\%\">
	<TR bgcolor=\"#00008b\" color=\"#ffffff\">";
	for ($i = 0;  $i < 5;  $i++) {
	     print "
	     <TD ALIGN=center><B><FONT size=\"1\" color=\"#ffffff\">@COLUMN[$i]</FONT></B></TD>";
	}
	print "</TR>\n";
	while ($REF = $STH->fetchrow_arrayref) {
		print "<TR bgcolor=\"#cccccc\">";
		for ($i = 0;  $i < 4;  $i++) {
			print "
			<TD><CENTER><FONT size=\"1\">$$REF[$i]</FONT></CENTER></TD>";
		}
		for ($i = 4;  $i < 5;  $i++) {
			$PROTOCOL=&ipproto($$REF[$i]);
			print "
			<TD><CENTER><FONT size=\"1\">$PROTOCOL</FONT></CENTER></TD>";
		}
		print "</TR></TABLE></CENTER>\n";
	}
	

		
##################################################################################################
# TCP layer
	
	if ($PROTOCOL eq "TCP"){

		$STH = $DBH->prepare($TCPHEADER_QUERY); # sending query to mysql
		$STH->execute();
		print "<H4>TCP header details</H4>\n";
		@COLUMN=("SRC PORT","DST PORT","WINDOW","FLAG","SEQUENCE");
	
		# printing the result TAB
		
		print "
		<CENTER>
		<TABLE BORDER=0 CELLPADDING=5 bgcolor=\"#aeaaae\" width=\"100\%\">
		<TR bgcolor=\"#00008b\">";
		for ($i = 0;  $i < 5;  $i++) {
			 print "
			 <TD ALIGN=center><B><FONT size=\"1\" color=\"#ffffff\">@COLUMN[$i]</FONT></B></TD>";
		}
		print "</TR>\n";
		while ($REF = $STH->fetchrow_arrayref) {
			print "<TR bgcolor=\"#cccccc\">";
			for ($i = 0;  $i < 2;  $i++) {
				my $PORT = $$REF[$i];
				
				if (($PORT < 1024)&&($PORT != 0)){
					my $SERVICE=getservbyport($PORT, 'tcp');
					print "
					<TD><CENTER><FONT size=\"1\">$SERVICE</FONT></CENTER></TD>";
				}else{
					print "
					<TD><CENTER><FONT size=\"1\">$PORT</FONT></CENTER></TD>";
				}
				
			}
			for ($i = 2;  $i < 5;  $i++) {
				print "
				<TD><CENTER><FONT size=\"1\">$$REF[$i]</FONT></CENTER></TD>";
			}
		print "</TR></TABLE></CENTER>\n";
		}
	
	
	
	}


##################################################################################################
# UDP layer

	if ($PROTOCOL eq "UDP"){
	
		$STH = $DBH->prepare($UDPHEADER_QUERY); # sending query to mysql
		$STH->execute();
		print "<H4>UDP header details</H4>\n";
		@COLUMN=("SRC PORT","DST PORT");
	
		# printing the result TAB
		
		print "
		<CENTER>
		<TABLE BORDER=0 CELLPADDING=5 bgcolor=\"#aeaaae\" width=\"100\%\">
		<TR bgcolor=\"#00008b\">";
		for ($i = 0;  $i < 2;  $i++) {
			 print "
			 <TD ALIGN=center><B><FONT size=\"1\" color=\"#ffffff\">@COLUMN[$i]</FONT></B></TD>";
		}
		print "</TR>\n";
		while ($REF = $STH->fetchrow_arrayref) {
			print "<TR bgcolor=\"#cccccc\">";
			for ($i = 0;  $i < 2;  $i++) {
				print "
				<TD><CENTER><FONT size=\"1\">$$REF[$i]</FONT></CENTER></TD>";
			}
		print "</TR></TABLE></CENTER>\n";
		}
		
		
		
	}

##################################################################################################
# ICMP layer
	
	if ($PROTOCOL eq "ICMP"){

		$STH = $DBH->prepare($ICMPHEADER_QUERY); # sending query to mysql
		$STH->execute();
		print "<H4>ICMP header details</H4>\n";
		@COLUMN=("ICMP TYPE","ICMP CODE","ICMP ID");
	
		# printing the result TAB
		
		print "
		<CENTER>
		<TABLE BORDER=0 CELLPADDING=5 bgcolor=\"#aeaaae\" width=\"100\%\">
		<TR bgcolor=\"#00008b\">";
		for ($i = 0;  $i < 3;  $i++) {
			 print "
			 <TD ALIGN=center><B><FONT size=\"1\" color=\"#ffffff\">@COLUMN[$i]</FONT></B></TD>";
		}
		print "</TR>\n";
		while ($REF = $STH->fetchrow_arrayref) {
			print "<TR bgcolor=\"#cccccc\">";
			for ($i = 0;  $i < 1;  $i++) {
				$TYPENUMBER=$$REF[$i];
				$ICMPTYPE=&icmptype($TYPENUMBER);
				print "
				<TD><CENTER><FONT size=\"1\">$ICMPTYPE</FONT></CENTER></TD>";
			}
			for ($i = 1;  $i < 2;  $i++) {
				if ($TYPENUMBER == 3){
					$ICMPCODE=icmp3code($$REF[$i]);
				}
				elsif ($TYPENUMBER == 5){
					$ICMPCODE=icmp5code($$REF[$i]);
				}
				elsif ($TYPENUMBER == 11){
					$ICMPCODE=icmp11code($$REF[$i]);
				}
				else{
					$ICMPCODE=$$REF[$i];
				}
				print "
				<TD><CENTER><FONT size=\"1\">$ICMPCODE</FONT></CENTER></TD>";
			}
			for ($i = 2;  $i < 3;  $i++) {
				print "
				<TD><CENTER><FONT size=\"1\">$$REF[$i]</FONT></CENTER></TD>";
			}
		print "</TR></TABLE></CENTER>\n";
		}
	}

	

	$STH->finish();
	$DBH->disconnect();
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

##################################################################################################
# DECODE FUNCTIONS 

sub ipproto{
	
	my %table;
	my $number = $_[0];



	$table{1} = "ICMP";
	$table{2} = "IGMP";
	$table{3} = "GGP";
	$table{4} = "IP";
	$table{5} = "ST";
	$table{6} = "TCP";
	$table{7} = "UCL";
	$table{8} = "EGP";
	$table{9} = "IGP";
	$table{10} = "BBN-RCC-MON";
	$table{11} = "NVP-II";
	$table{12} = "PUP";
	$table{13} = "ARGUS";
	$table{14} = "EMCON";
	$table{15} = "XNET";
	$table{16} = "CHAOS";
	$table{17} = "UDP";
	$table{18} = "MUX";
	$table{19} = "DCN-MEAS";
	$table{20} = "HMP";
	$table{21} = "PRM";
	$table{22} = "XNS-IDP";
	$table{23} = "TRUNK-1";
	$table{24} = "TRUNK-2";
	$table{25} = "LEAF-1";
	$table{26} = "LEAF-2";
	$table{27} = "RDP";
	$table{28} = "IRTP";
	$table{29} = "ISO-TP4";
	$table{30} = "NETBLT";
	$table{31} = "MFE-NSP";
	$table{32} = "MERIT-INP";
	$table{33} = "SEP";
	$table{34} = "3PC";
	$table{35} = "IDPR";
	
	
	
	if ($table{$number}){
		return $table{$number};
	}else{
		return $number;
	}

}

sub icmptype{
	
	my %table;
	my $number = $_[0];


	$table{0} = "Echo Reply";
	$table{3} = "Destination Unreachable";
	$table{4} = "Source Quench";
	$table{5} = "Redirect";
	$table{8} = "Echo Request";
	$table{11} = "Time Exceeded";
	$table{12} = "Parameter Problem";
	$table{13} = "Timestamp";
	$table{14} = "Timestamp Reply";
	$table{15} = "Information Request";
	$table{16} = "Information Reply";
	
	
	
	if ($table{$number}){
		return $table{$number};
	}else{
		return $number;
	}

}

sub icmp3code{
	
	my %table;
	my ($number) = $_[0];

	
	
	$table{0} = "net unreachable";
	$table{1} = "host unreachable";
	$table{2} = "protocol unreachable";
	$table{3} = "port unreachable";
	$table{4} = "fragmentation needed and DF set";
	$table{5} = "source route failed";
	
	
	
	if ($table{$number}){
		return $table{$number};
	}else{
		return $number;
	}

}

sub icmp5code{
	
	my %table;
	my ($number) = $_[0];

	$table{0} = "Network";
	$table{1} = "Host";
	$table{2} = "TOS and Network";
	$table{3} = "TOS and Host";
	
	if ($table{$number}){
		return $table{$number};
	}else{
		return $number;
	}

}

sub icmp11code{
	
	my %table;
	my ($number) = $_[0];				
	
	
	$table{0} = "ttl in transit";
	$table{1} = "frag reassembly";
	
	
	
	if ($table{$number}){
		return $table{$number};
	}else{
		return $number;
	}

}
