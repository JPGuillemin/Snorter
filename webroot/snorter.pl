#!/usr/bin/perl

print "Content-type: text/html\n";

# SNORTER v2.0

# Author : Jean Philippe Guillemin [ jpgu@users.sourceforge.net ]
# GNU GENERAL PUBLIC LICENSE http://www.gnu.org/copyleft/gpl.html


use CGI;
use DBI;
use GD::Graph::bars;
use GD::Graph::hbars;
use strict;


my %weight; # this is the metric database

$weight{'icmp-event'} = "0.01";
$weight{'misc-activity'} = "0.02";
$weight{'network-scan'} = "0.03";
$weight{'not-suspicious'} = "0.001";
$weight{'protocol-command-decode'} = "0.02";
$weight{'string-detect'} = "0.01";
$weight{'unknown'} = "0.01";

$weight{'bad-unknown'} = "0.2";
$weight{'attempted-dos'} = "0.02";
$weight{'attempted-recon'} = "0.02";
$weight{'denial-of-service'} = "0.5";
$weight{'misc-attack'} = "0.5";
$weight{'non-standard-protocol'} = "0.1";
$weight{'rpc-portmap-decode'} = "0.1";
$weight{'successful-dos'} = "0.1";
$weight{'successful-recon-largescale'} = "0.1";
$weight{'successful-recon-limited'} = "0.1";
$weight{'suspicious-filename-detect'} = "0.1";
$weight{'suspicious-login'} = "0.1";
$weight{'system-call-detect'} = "0.1";
$weight{'unusual-client-port-connection'} = "0.1";
$weight{'web-application-activity'} = "0.1";

$weight{'attempted-admin'} = "0.2";
$weight{'attempted-user'} = "0.2";
$weight{'shellcode-detect'} = "1";
$weight{'successful-admin'} = "1";
$weight{'successful-user'} = "1";
$weight{'trojan-activity'} = "0.5";
$weight{'unsuccessful-user'} = "0.5";
$weight{'web-application-attack'} = "0.2";
$weight{'policy-violation'} = "1";
$weight{'default-login-attempt'} = "0.5";

my %class; # this is a simple snort severity database

$class{'icmp-event'} = "low";
$class{'misc-activity'} = "low";
$class{'network-scan'} = "low";
$class{'not-suspicious'} = "low";
$class{'protocol-command-decode'} = "low";
$class{'string-detect'} = "low";
$class{'unknown'} = "low";

$class{'bad-unknown'} = "medium";
$class{'attempted-dos'} = "medium";
$class{'attempted-recon'} = "medium";
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

# These values are hostility metric thresholds the Main alerts tab
my $HOSTILE = 	1;
my $AGRESSIVE = 0.8 ;
my $CURIOUS = 	0.5;
my $PRUDENT = 	0.2;
my $SUSPECT = 	0.1;

# This is the global attack probability (don't touch until you know what you're doing)
my $global_prob = 0.5 ;

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
my $MEMPW=$CGI->param('mempw');
my $TARGET_DEL=$CGI->param('target_del');
my $TRUEIP=$CGI->param('trueip');
my $FALSEIP=$CGI->param('falseip');

if ($LIMIT eq ""){
		$LIMIT = "100";
}

if ($MINDATE eq ""){
		$MINDATE = date_only(time());
}

if ($MAXDATE eq ""){
		$MAXDATE = date_only(time());
}



my (	$HUMAN_DATE,
	$NUMBERHOST,
	@hosts,
	%hostility,
	%score,
	%bayes,
	%dispertion,
	%high,
	%medium,
	%low);


##################################################################################################
# Main program				


$HUMAN_DATE=sapiens(time());
&head();
&form();


if ($PASS ne ""){
# comment the &activity_graph(); line if you don't want bargraph		  #
	if ($TRUEIP) {
		&learn_true($TRUEIP);
		$TRUEIP = "";
	}
	if ($FALSEIP) {
		&learn_false($FALSEIP);
		$FALSEIP = "";
	}
	&refresh();
	&menu();
	&get_bayes();
	&statistics();
	&activity_graph();
	&attacks();
	&dispertion_graph();
	&sensors();

}else{
	&initialquery();
	
}
&foot();



##################################################################################################
# Loading events into memory and process hostility and dispertion criteria
 

sub statistics{
    my ($HOSTS_QUERY,
    	$SIGNATURE_QUERY,
	$TIME_QUERY,
	$DBH,
	$STH,
	$NUMBERFIELDS,
	$REF,
	$a1,
	$b1,
	$weight_buffer,
	$low_buffer,
	$medium_buffer,
	$high_buffer,
	$i);

	$HOSTS_QUERY="
	select inet_ntoa(iphdr.ip_src), count(iphdr.cid)
	from iphdr, event
	where iphdr.cid=event.cid and left(event.timestamp, 10) >= \"$MINDATE\" and left(event.timestamp, 10) <= \"$MAXDATE\" 
	group by iphdr.ip_src;";
	

	$DBH = DBI->connect("DBI:mysql:$DBNAME:$HOST","$USER","$PASS");

	$STH = $DBH->prepare($HOSTS_QUERY); # sending query to mysql
	$STH->execute();
	$NUMBERHOST = $STH->rows;
	$NUMBERFIELDS = $STH->{'NUM_OF_FIELDS'};	## number of fields in the result table

	# printing the result TAB
	
	while ($REF = $STH->fetchrow_arrayref) {
		push(@hosts,([$$REF[0],$$REF[1]]));
	}

	@hosts = sort {$a1 = $$a[1]; $b1 = $$b[1]; $b1 <=> $a1} @hosts;
	
	# now procceding with hostility
	for ($i = 0;  $i < $LIMIT;	$i++) {
		
		$SIGNATURE_QUERY="
			select sig_class.sig_class_name,signature.sig_sid
			from iphdr,event,signature,sig_class
			where inet_ntoa(iphdr.ip_src)=\"$hosts[$i][0]\" and iphdr.cid=event.cid and event.signature=signature.sig_id and sig_class.sig_class_id=signature.sig_class_id and left(event.timestamp, 10) >= \"$MINDATE\" and left(event.timestamp, 10) <= \"$MAXDATE\"
			order by sig_class.sig_class_name;";
		$STH = $DBH->prepare($SIGNATURE_QUERY); # sending query to mysql
		$STH->execute();
		
		$weight_buffer = 0;
		$low_buffer = 0;
		$medium_buffer = 0;
		$high_buffer = 0;
		while ($REF = $STH->fetchrow_arrayref) {
			if ($bayes{$$REF[1]}){
				$weight_buffer += ($weight{$$REF[0]} * $bayes{$$REF[1]});
			}else{
				$weight_buffer += $weight{$$REF[0]};
			}
			if ($class{$$REF[0]} eq "low") {$low_buffer ++};
			if ($class{$$REF[0]} eq "medium") {$medium_buffer ++};
			if ($class{$$REF[0]} eq "high") {$high_buffer ++};
		}
		$hostility{"$hosts[$i][0]"} = $weight_buffer;
		$low{"$hosts[$i][0]"} = $low_buffer;
		$medium{"$hosts[$i][0]"} = $medium_buffer;
		$high{"$hosts[$i][0]"} = $high_buffer;
		#print "$hosts[$i][0] --- $medium_buffer <BR>\n";
		
				
	}
	
	# now procceding with dispertion
	for ($i = 0;  $i < $LIMIT;	$i++) {
		
		$TIME_QUERY="
		select STD(UNIX_TIMESTAMP(event.timestamp)), MIN(UNIX_TIMESTAMP(event.timestamp)), MAX(UNIX_TIMESTAMP(event.timestamp))
		from iphdr,event,signature,sig_class
		where inet_ntoa(iphdr.ip_src)=\"$hosts[$i][0]\" and iphdr.cid=event.cid and left(event.timestamp, 10) >= \"$MINDATE\" and left(event.timestamp, 10) <= \"$MAXDATE\";";
		$STH = $DBH->prepare($TIME_QUERY); # sending query to mysql
		$STH->execute();
		
		$weight_buffer = 0;
		$low_buffer = 0;
		$medium_buffer = 0;
		$high_buffer = 0;
		while ($REF = $STH->fetchrow_arrayref) {
			$dispertion{"$hosts[$i][0]"} = $$REF[0]/($$REF[2]-$$REF[1]+1);
		}

	}

	$STH->finish();
	$DBH->disconnect();
}

##################################################################################################
# Get bayes probability	

sub get_bayes {

		my($FILE)="signature_bayes";
		my $line;
		my @buffer;


	open(PTR_FILE,$FILE) or die "Problem opening $FILE !";
	while($line=<PTR_FILE>) {
		@buffer = split (/:/,$line);
		# Bayes equation ##################
		if (($buffer[1])||($buffer[2])) {
			$bayes{$buffer[0]} = 2*(($buffer[1] * $global_prob) / ( ($buffer[1]* $global_prob) + ($buffer[2] * (1-$global_prob))));
		}
		#print "$buffer[0] $buffer[1] $buffer[2] $bayes{$buffer[0]} \n";
	}
	close(PTR_FILE);
}

##################################################################################################
# This one update the bayesian database from a true attack

sub learn_true{
    my ($SIGNATURE_QUERY,
	$DBH,
	$STH,
	$REF,
	$signature,
	$line,
	@buffer,
	%true_attack,
	%false_attack);
	
	my $IP = $_[0];
	my($FILE)="signature_bayes";

	
	open(PTR_FILE,$FILE) or die "Problem opening $FILE !";
	while($line=<PTR_FILE>) {
		chop($line);
		#if ($line =~ /^[0-9]+:[0-9]+:[0-9]+$/) { 
			@buffer = split (/:/,$line);
			$true_attack{$buffer[0]} = $buffer[1];
			$false_attack{$buffer[0]} = $buffer[2];
		#}
	}
	close(PTR_FILE);
			
	$SIGNATURE_QUERY="
		select signature.sig_sid 
		from iphdr,event,signature
		where inet_ntoa(iphdr.ip_src)=\"$IP\" and iphdr.cid=event.cid and event.signature=signature.sig_id and left(event.timestamp, 10) >= \"$MINDATE\" and left(event.timestamp, 10) <= \"$MAXDATE\"
		order by event.signature;";
	$DBH = DBI->connect("DBI:mysql:$DBNAME:$HOST","$USER","$PASS");
	$STH = $DBH->prepare($SIGNATURE_QUERY); # sending query to mysql
	$STH->execute();
	
	while ($REF = $STH->fetchrow_arrayref) {
		if ($true_attack{$$REF[0]}){
			$true_attack{$$REF[0]} += 0.01;
		}else{
			$true_attack{$$REF[0]} = 0.5;
			$true_attack{$$REF[0]} += 0.01;
			$false_attack{$$REF[0]} = 0.5;
		}
	}
	
	open(PTR_FILE, ">$FILE") or die "Problem opening $FILE !";
	
	foreach $signature (keys(%true_attack)) {
		#print "$signature\n";
		print PTR_FILE "$signature".':'."$true_attack{$signature}".':'."$false_attack{$signature}".':'."\n";
	}
	close(PTR_FILE);				

	$STH->finish();
	$DBH->disconnect();
}


##################################################################################################
# This one update the bayesian database from a false positive

sub learn_false{
    my ($SIGNATURE_QUERY,
	$DBH,
	$STH,
	$REF,
	$signature,
	$line,
	@buffer,
	%true_attack,
	%false_attack);
	
	my $IP = $_[0];
	my($FILE)="signature_bayes";

	
	open(PTR_FILE,$FILE) or die "Problem opening $FILE !";
	while($line=<PTR_FILE>) {
		chop($line);
		#if ($line =~ /^[0-9]+:[0-9]+:[0-9]+$/) { 
			@buffer = split (/:/,$line);
			$true_attack{$buffer[0]} = $buffer[1];
			$false_attack{$buffer[0]} = $buffer[2];
		#}
	}
	close(PTR_FILE);
			
	$SIGNATURE_QUERY="
		select signature.sig_sid
		from iphdr,event,signature
		where inet_ntoa(iphdr.ip_src)=\"$IP\" and iphdr.cid=event.cid and event.signature=signature.sig_id and left(event.timestamp, 10) >= \"$MINDATE\" and left(event.timestamp, 10) <= \"$MAXDATE\"
		order by event.signature;";
	$DBH = DBI->connect("DBI:mysql:$DBNAME:$HOST","$USER","$PASS");
	$STH = $DBH->prepare($SIGNATURE_QUERY); # sending query to mysql
	$STH->execute();
	
	while ($REF = $STH->fetchrow_arrayref) {
		if ($false_attack{$$REF[0]}){
			$false_attack{$$REF[0]} += 0.01;
		}else{
			$false_attack{$$REF[0]} = 0.5;
			$false_attack{$$REF[0]} += 0.01;
			$true_attack{$$REF[0]} = 0.5;
		}
	}
	
	open(PTR_FILE, ">$FILE") or die "Problem opening $FILE !";
	
	foreach $signature (keys(%false_attack)) {
		print PTR_FILE "$signature".':'."$true_attack{$signature}".':'."$false_attack{$signature}".':'."\n";
	}
	close(PTR_FILE);				

	$STH->finish();
	$DBH->disconnect();
}


##################################################################################################
# Sources IP sorted / number of alerts  


sub attacks{
	my ($i,
		@COLUMN,
		$SIP,
		$color);

	@COLUMN=("Whois query","World map","SOURCE IP\@","Low","Medium","High","Hostility", "Bayes true", "Bayes false");

	# printing the result TAB
	print "<a name=\"0\"></a>";
	print "<H3>Attack source(s) from $MINDATE to $MAXDATE :</H3>\n";
	print "
		<CENTER>\n
		<TABLE BORDER=0 CELLPADDING=6 bgcolor=\"#aeaaae\" width=\"100\%\">\n
		<TR bgcolor=\"#00008b\">";
	for ($i = 0;  $i < 9;  $i++) {
			print "<TD ALIGN=center><B><FONT size=\"1\" color=\"#ffffff\">@COLUMN[$i]</FONT></B></TD>";
	}
	
	print "</TR>\n";
		for ($i = 0;  $i < $LIMIT;	$i++) {
			$SIP = $hosts[$i][0];
			CASE: {
			   ($hostility{$SIP} >= $HOSTILE) && do{
				   $color="#bf0000";
				   last CASE;
			   };			
			   ($hostility{$SIP} >= $AGRESSIVE) && do{
				   $color="#ff7f00";
				   last CASE;
			   };
			   ($hostility{$SIP} >= $CURIOUS) && do{
				   $color="#fff600";
				   last CASE;
			   };
			   ($hostility{$SIP} >= $PRUDENT) && do{
				   $color="#0000bf";
				   last CASE;
			   };
			   ($hostility{$SIP} >= $SUSPECT) && do{
				   $color="#5ba8f5";
				   last CASE;
			   };
			   ($hostility{$SIP} < $SUSPECT) && do{
				   $color="#75C4F5";
				   last CASE;
			   };
			   
		} # end of CASE block
			if ($i % 2) {
						print "<TR bgcolor=\"#cccccc\">";
					}else{
						print "<TR bgcolor=\"#bbbbbb\">";		
					}
			print "
			<TD ALIGN=center><A HREF=\"http://www.ripe.net/perl/whois\?searchtext=".$SIP."\" TARGET=new>
			<IMG BORDER=0 width=24 height=24 SRC=\"./ripe.gif\" ALT=\"Whois\"></A></TD>
			<TD ALIGN=center><A HREF=\"http://www.antionline.com/tools-and-toys/ip-locate/index.php?address=".$SIP."\" TARGET=new>
			<IMG BORDER=0 width=24 height=24 SRC=\"./world.gif\" ALT=\"Whois\"></A></TD>
			<TD ALIGN=center><FONT size=\"1\">
			<FORM ACTION=\"alerts.pl\" METHOD= post > \n
			<INPUT TYPE=\"hidden\" NAME=\"pw\" VALUE=".$PASS.">\n
			<INPUT TYPE=\"hidden\" NAME=\"mempw\" VALUE=".$MEMPW.">\n
			<INPUT TYPE=\"hidden\" NAME=\"host\" VALUE=".$HOST.">\n
			<INPUT TYPE=\"hidden\" NAME=\"db\" VALUE=".$DBNAME.">\n
			<INPUT TYPE=\"hidden\" NAME=\"user\" VALUE=".$USER.">\n
			<INPUT TYPE=\"hidden\" NAME=\"hacker\" VALUE=".$SIP.">\n
			<INPUT TYPE=\"hidden\" NAME=\"limit\" VALUE=".$LIMIT.">\n
			<INPUT TYPE=\"hidden\" NAME=\"mindate\" VALUE=".$MINDATE.">\n
			<INPUT TYPE=\"hidden\" NAME=\"maxdate\" VALUE=".$MAXDATE.">\n
			<INPUT TYPE=\"submit\" NAME=\"submitButtonName\" VALUE=$SIP>\n
			</FORM></FONT></TD>\n
			<TD ALIGN=center><FONT size=\"1\">".$low{$SIP}."</FONT></TD>\n
			<TD ALIGN=center><FONT size=\"1\">".$medium{$SIP}."</FONT></TD>\n
			<TD ALIGN=center><FONT size=\"1\">".$high{$SIP}."</FONT></TD>\n
			<TD ALIGN=center bgcolor=\"$color\"><FONT size=\"1\"> $hostility{$SIP} </FONT></TD>
			<TD ALIGN=center><FONT size=\"1\">
			<FORM ACTION=\"snorter.pl\" METHOD= post > \n
			<INPUT TYPE=\"hidden\" NAME=\"pw\" VALUE=".$PASS.">\n
			<INPUT TYPE=\"hidden\" NAME=\"mempw\" VALUE=".$MEMPW.">\n
			<INPUT TYPE=\"hidden\" NAME=\"host\" VALUE=".$HOST.">\n
			<INPUT TYPE=\"hidden\" NAME=\"db\" VALUE=".$DBNAME.">\n
			<INPUT TYPE=\"hidden\" NAME=\"user\" VALUE=".$USER.">\n
			<INPUT TYPE=\"hidden\" NAME=\"hacker\" VALUE=".$SIP.">\n
			<INPUT TYPE=\"hidden\" NAME=\"limit\" VALUE=".$LIMIT.">\n
			<INPUT TYPE=\"hidden\" NAME=\"mindate\" VALUE=".$MINDATE.">\n
			<INPUT TYPE=\"hidden\" NAME=\"maxdate\" VALUE=".$MAXDATE.">\n
			<INPUT TYPE=\"hidden\" NAME=\"trueip\" VALUE=".$SIP.">\n
			<INPUT TYPE=\"submit\" NAME=\"submitButtonName\" VALUE=\"true\">\n
			</FORM></FONT></TD>
			<TD ALIGN=center><FONT size=\"1\">
			<FORM ACTION=\"snorter.pl\" METHOD= post > \n
			<INPUT TYPE=\"hidden\" NAME=\"pw\" VALUE=".$PASS.">\n
			<INPUT TYPE=\"hidden\" NAME=\"mempw\" VALUE=".$MEMPW.">\n
			<INPUT TYPE=\"hidden\" NAME=\"host\" VALUE=".$HOST.">\n
			<INPUT TYPE=\"hidden\" NAME=\"db\" VALUE=".$DBNAME.">\n
			<INPUT TYPE=\"hidden\" NAME=\"user\" VALUE=".$USER.">\n
			<INPUT TYPE=\"hidden\" NAME=\"hacker\" VALUE=".$SIP.">\n
			<INPUT TYPE=\"hidden\" NAME=\"limit\" VALUE=".$LIMIT.">\n
			<INPUT TYPE=\"hidden\" NAME=\"mindate\" VALUE=".$MINDATE.">\n
			<INPUT TYPE=\"hidden\" NAME=\"maxdate\" VALUE=".$MAXDATE.">\n
			<INPUT TYPE=\"hidden\" NAME=\"falseip\" VALUE=".$SIP.">\n
			<INPUT TYPE=\"submit\" NAME=\"submitButtonName\" VALUE=\"false\">\n
			</FORM></FONT></TD>\n";
			print "</TR>\n";
		}

	print "
	</TABLE></CENTER>\n";

}

##################################################################################################
# Activity graph	(10 most active IP) 

sub activity_graph{
	my ($i,
		@LOW_ALERTS,
		@MEDIUM_ALERTS,
		@HIGH_ALERTS,
		@IP,
		$NUM_ANGRY,
		$DBH,
		$STH,
		$REF,
		@data,
		$GRAPH,
		$IMAGE,
		$png);


	for ($i = 0;  $i < 10;  $i++) {
		if ($hosts[$i][1] ne ""){
			@IP[$i] = $hosts[$i][0];
			@LOW_ALERTS[$i] = $low{"$hosts[$i][0]"};
			@MEDIUM_ALERTS[$i] = $medium{"$hosts[$i][0]"};
			@HIGH_ALERTS[$i] = $high{"$hosts[$i][0]"};
			$NUM_ANGRY=$i+1;
		}else{
			@IP[$i] ="";
			@LOW_ALERTS[$i]="";
			@MEDIUM_ALERTS[$i]="";
			@HIGH_ALERTS[$i]="";
		}
	}

	@data = ([@IP], [@LOW_ALERTS], [@MEDIUM_ALERTS], [@HIGH_ALERTS]);

	$GRAPH = GD::Graph::bars->new(850, 200);
	$GRAPH->set( dclrs => [ qw(blue orange red) ] );

	$GRAPH->set(
	x_label	    => 'Hosts',
	y_label	    => 'Number of alerts by type',
	title	    => 'Activity',
	bar_width   => 5,
	show_values => 1,
	bar_spacing     => 8,
	shadow_depth    => 2,
	shadowclr       => 'grey75',
	) or warn $GRAPH->error;
	$GRAPH->set_legend_font(GD::gdMediumBoldFont);
	$GRAPH->set_x_axis_font(GD::gdTinyFont);
	$GRAPH->set_y_axis_font(GD::gdMediumBoldFont);
	$GRAPH->set_x_label_font(GD::gdMediumBoldFont);
	$GRAPH->set_y_label_font(GD::gdMediumBoldFont);
	$GRAPH->set_title_font(GD::gdMediumBoldFont);
	$GRAPH->set_legend( 'Low', 'Medium', 'High' );
	$IMAGE = $GRAPH->plot(\@data) or die $GRAPH->error;
	$png=$IMAGE->png;
	open (IMAGE,">img1.png");
	binmode IMAGE;
	print IMAGE $png;
	close(IMAGE);

	print "<H3>$NUM_ANGRY most active host(s) from $MINDATE to $MAXDATE :</H3>\n";
	print "<a name=\"1\"></a>";
	print "<CENTER><TABLE BORDER=0 CELLPADDING=6 bgcolor=\"#ffffff\"><TR><TD>\n";
	print "<CENTER><IMG BORDER=1 SRC=\"img1.png\"></IMG></CENTER>\n";
	print "</TD></TR></TABLE></CENTER>\n";

}


##################################################################################################
# Dispertion graph	 

sub dispertion_graph{
	my ($i,
		@DISP,
		@IP,
		$NUM_ANGRY,
		$DBH,
		$STH,
		$REF,
		@data,
		$GRAPH,
		$IMAGE,
		$png);


	for ($i = 0;  $i < 10;  $i++) {
		if ($hosts[$i][1] ne ""){
			@IP[$i] = $hosts[$i][0];
			@DISP[$i] = $dispertion{"$hosts[$i][0]"};
			$NUM_ANGRY=$i+1;
		}else{
			@IP[$i] ="";
			@DISP[$i]="";
		}
	}

	@data = ([@IP], [@DISP]);

	$GRAPH = GD::Graph::hbars->new(850, 200);
	$GRAPH->set( dclrs => [ qw(grey blue) ] );

	$GRAPH->set(
	x_label	    => 'Hosts',
	y_label	    => 'Dispertion',
	title	    => 'Dispertion of alerts',
	#bar_spacing => 4,
	#bar_width   => 5,
	show_values => 1,
	) or warn $GRAPH->error;
	$GRAPH->set_legend_font(GD::gdMediumBoldFont);
	$GRAPH->set_x_axis_font(GD::gdTinyFont);
	$GRAPH->set_y_axis_font(GD::gdMediumBoldFont);
	$GRAPH->set_x_label_font(GD::gdMediumBoldFont);
	$GRAPH->set_y_label_font(GD::gdMediumBoldFont);
	$GRAPH->set_title_font(GD::gdMediumBoldFont);
	$GRAPH->set_legend( 'Standard deviation (sec)' );
	$IMAGE = $GRAPH->plot(\@data) or die $GRAPH->error;
	$png=$IMAGE->png;
	open (IMAGE,">img2.png");
	binmode IMAGE;
	print IMAGE $png;
	close(IMAGE);


	
	print "<H3>Time dispertion of alerts from $MINDATE to $MAXDATE :</H3>\n";
	print "<a name=\"2\"></a>";
	print "<CENTER><TABLE BORDER=0 CELLPADDING=6 bgcolor=\"#ffffff\"><TR><TD>\n";
	print "<CENTER><IMG BORDER=1 SRC=\"img2.png\"></IMG></CENTER>\n";
	print "</TD></TR></TABLE></CENTER>\n";

}

##################################################################################################
# Sensors report 


sub sensors{
	my ($SENSORS_QUERY,
	$i,
	$DBH,
	$STH,
	$NUMBERFIELDS,
	$NUMBEROW,
	@COLUMN,
	$REF);
	
	$SENSORS_QUERY="
		SELECT sid,hostname,interface
		FROM sensor
		ORDER BY sid;";
	$DBH = DBI->connect("DBI:mysql:$DBNAME:$HOST","$USER","$PASS");

	$STH = $DBH->prepare($SENSORS_QUERY); # sending query to mysql
	$STH->execute();
	$NUMBEROW = $STH->rows;
	$NUMBERFIELDS = $STH->{'NUM_OF_FIELDS'};	## number of fields in the result table
	# $COLUMNAME = $STH->{'NAME'};
	@COLUMN=("SENSOR ID","ADDRESS","INTERFACE");

	# printing the result TAB
	print "<a name=\"3\"></a>";
	print "<H3>$NUMBEROW Sensor(s) :</H3>\n";

	print "
	<CENTER>\n
	<TABLE BORDER=0 CELLPADDING=6 bgcolor=\"#00008b\" width=\"100\%\">\n
	<TR>";
	for ($i = 0;  $i < 3;  $i++) {
	     print "<TD ALIGN=center><B><FONT size=\"1\" color=\"#ffffff\">@COLUMN[$i]</FONT></B></TD></FONT>";
	}
	print "</TR>\n";
	while ($REF = $STH->fetchrow_arrayref) {
		print "<TR>";

		for ($i = 0;  $i < 1;  $i++) {
			print "<TD ALIGN=center><FONT size=\"1\" color=\"#ffffff\">$$REF[$i]</FONT></TD>";
			}
		for ($i = 1;  $i < 2;  $i++) {
			print "<TD ALIGN=center><FONT size=\"1\" color=\"#ffffff\">$$REF[$i]</FONT></TD>";
		}
		for ($i = 2;  $i < 3;  $i++) {
			print "<TD ALIGN=center><FONT size=\"1\" color=\"#ffffff\">$$REF[$i]</FONT></TD>";
		}
		print "</TR>\n";
	}
	print "
	</TABLE></CENTER>\n";
	#print "<P><B>sql :  </B>".$SENSORS_QUERY."</p>\n";  # debug
	$STH->finish();
	$DBH->disconnect();
}	


##################################################################################################
# FORM       


sub form {

	print "
	<H3>General parameters :</H3> \n
	<FORM ACTION=\"snorter.pl\" METHOD= post > \n
	<CENTER><TABLE BORDER=0 CELLPADDING=5 bgcolor=\"#00008b\" width=\"100\%\"><TR> \n";
	if ($HOST ne ""){
		print "<TD align=center ><FONT color=\"#ffffff\"><b>DB Host :</b></FONT><INPUT TYPE=\"text\" NAME=\"host\" VALUE=".$HOST." size=\"24\"> </TD>";
	}else{
		print "<TD align=center ><FONT color=\"#ffffff\"><b>DB Host :</b></FONT><INPUT TYPE=\"text\" NAME=\"host\" size=\"24\"> </TD>";
	}
	if ($DBNAME ne ""){
		print "<TD align=center ><FONT color=\"#ffffff\"><b>DB Name :</b></FONT><INPUT TYPE=\"text\" NAME=\"db\" VALUE=".$DBNAME." size=\"24\"> </TD>";
	}else{
		print "<TD align=center ><FONT color=\"#ffffff\"><b>DB Name :</b></FONT><INPUT TYPE=\"text\" NAME=\"db\" size=\"24\"> </TD>";
	}
	if ($USER ne ""){
		print "<TD align=center ><FONT color=\"#ffffff\"><b>DB User :</b></FONT><INPUT TYPE=\"text\" NAME=\"user\" VALUE=".$USER." size=\"24\"> </TD>";
	}else{
		print "<TD align=center ><FONT color=\"#ffffff\"><b>DB User :</b></FONT><INPUT TYPE=\"text\" NAME=\"user\" size=\"24\"> </TD>";
	}
	if ($PASS ne "" && $MEMPW eq "on") {
		print "<TD align=center ><FONT color=\"#ffffff\"><b>DB Pass :</b></FONT><INPUT TYPE=\"password\" NAME=\"pw\" VALUE=".$PASS." size=\"24\"> </TD>";
	}else{
		print "<TD align=center ><FONT color=\"#ffffff\"><b>DB Pass :</b></FONT><INPUT TYPE=\"password\" NAME=\"pw\" size=\"24\"> </TD>";
	}
	if ($MEMPW ne "on") {
		print "<TD align=center ><FONT color=\"#ffffff\"><b>Remember PW ?</b></FONT><INPUT TYPE=\"checkbox\" NAME=mempw > </TD>";
	}else{
		print "<TD align=center ><FONT color=\"#ffffff\"><b>Remember PW ?</b></FONT><INPUT TYPE=\"checkbox\" NAME=mempw CHECKED > </TD>";
	}
	print "
	</TR></TABLE> </CENTER>\n";
}


sub menu {
	print "
	<TABLE BORDER=0 CELLPADDING=6 bgcolor=\"#bbbbbb\" width=\"100\%\" ><TR> \n
	<TD ALIGN=center><B><FONT color=\"#339966\"><a color=\"#000000\" href=\"#1\">Activity graph</a></FONT></B></TD>
	<TD ALIGN=center><B><FONT color=\"#339966\"><a color=\"#000000\" href=\"#0\">Sources classification</a></FONT></B></TD>
	<TD ALIGN=center><B><FONT color=\"#339966\"><a color=\"#000000\" href=\"#2\">Dispertion graph</a></FONT></B></TD>
	<TD ALIGN=center><B><FONT color=\"#339966\"><a color=\"#000000\" href=\"#3\">Sensors</a></FONT></B></TD>
	</TD></TR></TABLE><BR> \n";
}

sub initialquery {	
	print "
	<TABLE BORDER=0 CELLPADDING=6 bgcolor=\"#00008b\" width=\"100\%\" ><TR> \n
	<TD ALIGN=center rowspan=2> \n
	<P><INPUT TYPE=\"submit\" NAME=\"submitButtonName\" VALUE=\"Send query\"> \n
  </P> \n
    	</TD></TR>\n
</TABLE></FORM> \n
    <BR> \n";
}

sub refresh {
	print "
	<TABLE BORDER=0 CELLPADDING=6 bgcolor=\"#00008b\" width=\"100\%\" ><TR> \n
	<TD align=center ><FONT color=\"#ffffff\"><b>Min date : </b></FONT><INPUT TYPE=\"text\" name=\"mindate\" value=$MINDATE size=\"10\"> </TD>
	<TD align=center ><FONT color=\"#ffffff\"><b>Max date : </b></FONT><INPUT TYPE=\"text\" name=\"maxdate\" value=$MAXDATE size=\"10\"> </TD>
	<TD ALIGN=center> \n
	<TD align=center ><FONT color=\"#ffffff\"><b>Limit : </b></FONT><INPUT TYPE=\"text\" name=\"limit\" value=$LIMIT size=\"10\"> </TD>
	<TD ALIGN=center> \n
	<P><INPUT TYPE=\"submit\" NAME=\"submitButtonName\" VALUE=\"Refresh\"> \n
    	</TD></TR></TABLE></FORM><BR> \n";
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

sub date_only {
	my ($DATE,$SEC,$MIN,$HOUR,$MDAY,$MONTH,$YEAR,$SDAY,$ADAY,$ISDST);
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
	$DATE = "$YEAR-$MONTH-$MDAY";
return $DATE
}

