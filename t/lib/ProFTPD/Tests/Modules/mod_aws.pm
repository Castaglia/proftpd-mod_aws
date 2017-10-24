package ProFTPD::Tests::Modules::mod_aws;

use lib qw(t/lib);
use base qw(ProFTPD::TestSuite::Child);
use strict;

use Carp;
use File::Copy;
use File::Path qw(mkpath);
use File::Spec;
use IO::Handle;
use Socket;

use ProFTPD::TestSuite::FTP;
use ProFTPD::TestSuite::Utils qw(:auth :config :running :test :testsuite);

$| = 1;

my $order = 0;

my $TESTS = {
  aws_non_ec2_startup => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  aws_health_check => {
    order => ++$order,
    test_class => [qw(forking)],
  },

};

sub new {
  return shift()->SUPER::new(@_);
}

sub list_tests {

  # Check for the required Perl modules:
  #
  #  LWP-UserAgent

  my $required = [qw(
    LWP::UserAgent
  )];

  foreach my $req (@$required) {
    eval "use $req";
    if ($@) {
      print STDERR "\nWARNING:\n + Module '$req' not found, skipping all tests\n";

      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Unable to load $req: $@\n";
      }

      return qw(testsuite_empty_test);
    }
  }

  return testsuite_get_runnable_tests($TESTS);
}

sub aws_non_ec2_startup {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'aws');

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'aws:20 aws.http:20 aws.instance:20 aws.sign:20 event:20',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_aws.c' => {
        AWSEngine => 'on',
        AWSLog => $setup->{log_file},
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  my $ex;

  # This should not fail.
  eval { server_start($setup->{config_file}) };
  if ($@) {
    $ex = $@;

  } else {
    # Give the server a chance to startup
    sleep(10);

    eval { server_stop($setup->{pid_file}) };
    if ($@) {
      $ex = $@;
    }
  }

  # Now check the logs to see what we wrote.
  eval {
    if (open(my $fh, "< $setup->{log_file}")) {
      while (my $line = <$fh>) {
        chomp($line);

        if ($ENV{TEST_VERBOSE}) {
          print STDERR "# $line\n";
        }
      }

      close($fh);

    } else {
      die("Can't read $setup->{log_file}: $!");
    }
  };
  if ($@) {
    $ex = $@;
  }

  test_cleanup($setup->{log_file}, $ex);
}

sub aws_health_check {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'aws');

  my $healthcheck_uri = '/health';
  my $healthcheck_addr = '127.0.0.1';
  my $healthcheck_port = 8080;

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'aws:20 aws.health:20',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_aws.c' => {
        AWSEngine => 'on',
        AWSHealthCheck => "$healthcheck_uri $healthcheck_addr $healthcheck_port",
        AWSLog => $setup->{log_file},
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  require LWP::UserAgent;

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      # Let the server start up
      sleep(10);

      my $agent = LWP::UserAgent->new();
      $agent->timeout(2);

      my $url = "http://$healthcheck_addr:$healthcheck_port$healthcheck_uri";
      if ($ENV{TEST_VERBOSE}) {
        print STDERR "# Calling AWSHealthCheck $url\n";
      }

      my $response = $agent->get($url);
      $self->assert(defined($response), "Failed to call $url");

      my $status = $response->status_line;
      my $message = $response->message;

      if ($ENV{TEST_VERBOSE}) {
        print STDERR "# Health: Status: $status\n";
        print STDERR "# Health: Message: $message\n";

        if ($status !~ /^200/) {
          use Data::Dumper;
          print STDERR "# Response: ", Dumper($response), "\n";
        }
      }

      $self->assert(qr/^200/, $status,
        "Expected 200 response, got '$status'");
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh, 30) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($setup->{pid_file});
  $self->assert_child_ok($pid);

  test_cleanup($setup->{log_file}, $ex);
}

1;
