#!/usr/bin/perl

# Add new moduli to list of known numbers


sub usage
{
	print "moduli2match <moduli> <match-DB>\n";
	exit(1);
}

my $moduli = shift || usage();
my $match = shift || usage();

open(MODULI, "<$moduli") or die $!;
open(MATCH, "<$match") or die $!;

my $line = "";
my %match_keys = ();
while ($line = <MATCH>) {
	next if ($line =~ /#.+/);
	$line =~ s/\n//;
	my ($k, $x) = split /,/, $line;
	$match_keys{$k} = 1;
}
close(MATCH);

print "Found ".scalar(keys %match_keys)." numbers in $match\n";

open(MATCH,">>$match") or die $!;

my $newkeys = 0;
while ($line = <MODULI>) {
	next if ($line =~ /#.+/);
	$line =~ s/\n//;
	my @l = split / /, $line;
	if (!defined $match_keys{$l[6]}) {
		print MATCH $l[6] . ",OpenSSH moduli,\n";
		++$newkeys;
	}
}

close(MATCH);
close(MODULI);

print "Imported $newkeys new SSH modulis.\n";


