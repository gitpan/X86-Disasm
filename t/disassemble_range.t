# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl disassemble_range.t'

#########################

use Test::More tests => 7;

our (@range_data, $count);

BEGIN { use_ok('X86::Disasm', qw(
$x86_asm_format
$x86_asm_format_enum
$x86_options
$x86_op_foreach_type
$x86_report_codes
)) };

#8d 4c 24 04            lea    0x4(%esp),%ecx
#83 e4 f0               and    $0xfffffff0,%esp
#ff 71 fc               pushl  -0x4(%ecx)
#55                     push   %ebp
#89 e5                  mov    %esp,%ebp
#51                     push   %ecx

my $buffer = "\x8d\x4c\x24\x04\x83\xe4\xf0\xff\x71\xfc\x55\x89\xe5\x51";
my $buf_rva = 0;
my $offset = 4;
my $length = 10;

$count = 0;
my $callback_data = {format => $x86_asm_format_enum->{'att_syntax'}, colour => "purple", count => \$count, list => \@range_data};

my $callback_ref = sub {
  my $insn = shift;
  my $data =  shift;

  $data->{list}->[${$data->{count}}++] = $insn->format_insn($data->{format});
};

my $disasm = X86::Disasm->new;
$disasm->disassemble_range($buffer, $buf_rva, $offset, $length, $callback_ref, $callback_data);
ok($range_data[0] eq 'and	$0xF0, %esp');
ok($range_data[1] eq 'pushl	-0x4(%ecx)');
ok($range_data[2] eq 'push	%ebp');
ok($range_data[3] eq 'mov	%esp, %ebp');
ok($range_data[4] eq 'push	%ecx');

$offset = 0;
$length = 4;
$count = 0;
undef @range_data;
$disasm->disassemble_range(\$buffer, $buf_rva, $offset, $length, $callback_ref, $callback_data);
ok($range_data[0] eq 'leal	0x4(%esp), %ecx');
