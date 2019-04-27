#!/usr/bin/perl

my @vars = (
    "BUCKET",
    "BASE_URL",
    "PINPOINT_APPLICATION_ID",
    "SQUARE_LOCATION_ID",
    "SQUARE_ACCESS_TOKEN",
    "SQUARE_APPLICATION_ID",
    "AUTHORIZE_NET_LOGIN_KEY",
    "AUTHORIZE_NET_TRANSACTION_KEY",
    "AUTHORIZE_NET_ENV",
    "PARTITION",
    "AWS_REGION",
    "ACCOUNT_ID",
    "PROJECT_ID"
);

my $file = "template-configuration.json";

undef $/;

open(INPUT, $file) || die;
$_ = <INPUT>;
close INPUT;

for my $var (@vars) {
    s/\$$var\$/$ENV{$var}/e;
}

open(OUTPUT, ">$file") || die;
print OUTPUT $_;
close OUTPUT;
