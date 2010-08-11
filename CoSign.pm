# Movable Type (r) Open Source (C) 2001-2009 Six Apart, Ltd.
# This program is distributed under the terms of the
# GNU General Public License, version 2.

package MT::Auth::CoSign;

use strict;
use Net::LDAP;
use base 'MT::Auth::MT';
use MT::Author qw(AUTHOR);

sub can_recover_password { 0 }
sub is_profile_needed { 1 }
sub password_exists { 0 }
sub delegate_auth { 1 }
sub can_logout { 1 }
sub favorite_blogs { [] }

sub new_user {
    my $auth = shift;
    my ($app, $user) = @_;
    $user->password('(none)');

    my $ldap = Net::LDAP->new('ldap.example.com') or return 0;
    $ldap->bind(version => 3);

    my $entry = $ldap->search(
        base   => 'ou=people,dc=example,dc=com',
        scope  => 'sub',
        filter => '(uid=' . $user->name . ')',
        attrs  => [ 'givenName', 'sn', 'mail' ]
    )->entry(0);

    $user->email($entry->get_value('mail'));
    $user->nickname($entry->get_value('givenName') . ' ' . $entry->get_value('sn'));

    $ldap->unbind;
    $user->save;
    1;
}

sub remote_user {
    my $auth = shift;
    my ($ctx) = @_;
    if ($ENV{MOD_PERL}) {
        my $app = $ctx->{app} or return;
        return $app->{apache}->connection->user;
    }
    $ENV{HTTP_X_FORWARDED_USER}
}

sub fetch_credentials {
    my $auth = shift;
    my ($ctx) = @_;
    my $remote_user = $auth->remote_user($ctx);
    my $fallback = { %$ctx, username => $remote_user };
    $ctx = $auth->SUPER::session_credentials(@_);
    if (!defined $ctx) {
        if ($remote_user) {
            $ctx = $fallback;
        } else {
            return undef;
        }
    }
    if ($ctx->{username} ne $remote_user) {
        $ctx = $fallback;
    }
    $ctx;
}

sub validate_credentials {
    my $auth = shift;
    my ($ctx, %opt) = @_;

    my $app = $ctx->{app};
    my $user = $ctx->{username};
    return undef unless (defined $user) && ($user ne '');

    my $result = MT::Auth::UNKNOWN();

    # load author from db
    my $author = MT::Author->load({ name => $user, type => AUTHOR, auth_type => $app->config->AuthenticationModule });
    if ($author) {
        # author status validation
        if ($author->is_active) {
            $result = MT::Auth::SUCCESS();
            $app->user($author);

            $result = MT::Auth::NEW_LOGIN()
                unless $app->session_user($author, $ctx->{session_id}, %opt);
        } else {
            $result = MT::Auth::INACTIVE();
        }
    } else {
        if ($app->config->ExternalUserManagement) {
            $result = MT::Auth::NEW_USER();
        }
    }

    return $result;
}

1;

__END__
