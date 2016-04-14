use inc::Module::Install;

name 'FBOS';
all_from 'lib/FBOS.pm';
license 'perl';

build_requires 'Test::More';
requires 'LWP::UserAgent' => '0';
requires 'JSON' => '0';
requires 'Storable' => '0';
requires 'Digest::HMAC_SHA1' => '0';
requires 'MIME::Base64' => '0';

test =>
  { TESTS => q[t/00_load.t] };

auto_install;

WriteAll;
