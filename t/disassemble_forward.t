# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl disassemble_forward.t'

#########################

use Test::More tests => 6;

our (@forward_data, $count);

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

$count = 0;

my $callback_ref = sub {
  my $insn = shift;
  my $data =  shift;

  $data->{list}->[${$data->{count}}++] = $insn->format_insn($data->{format});
};

my $callback_data = {format => $x86_asm_format_enum->{'att_syntax'}, colour => "purple", count => \$count, list => \@forward_data};

my $resolver_ref = sub {
  my $op = shift;
  my $insn = shift;
  my $data = shift;

  my $next_addr = -1;

  if ($x86_op_type->{$op->type} eq 'op_absolute' || 
      $x86_op_type->{$op->type} eq 'op_offset') {
    $next_addr = $op->sdword;
  } elsif ($x86_op_type->{$op->type} eq 'op_relative_near' ||
           $x86_op_type->{$op->type} eq 'op_relative_far') {
# add offset to current rva+size based on op size
     if ( $x86_op_datatype{$op->datatype} eq 'op_byte' ) {
       $next_addr = $insn->addr + $insn->size + $op->sbyte;
     } elsif ( $x86_op_datatype{$op->datatype} eq 'op_word' ) {
       $next_addr = $insn->addr + $insn->size + $op->sword;
     } elsif ( $x86_op_datatype{$op->datatype} eq 'op_dword' ) {
       $next_addr = $insn->addr + $insn->size + $op->sdword;
     }
  }

  return $next_addr;
};

my $resolver_data = {format => $x86_asm_format_enum->{'att_syntax'}, colour => "purple"};

my $offset = 4;
my $disasm = X86::Disasm->new;
my $retval = $disasm->disassemble_forward($buffer, $buf_rva, $offset, $callback_ref, $callback_data, $resolver_ref, $resolver_data);
ok($forward_data[0] eq 'and	$0xF0, %esp');
ok($forward_data[1] eq 'pushl	-0x4(%ecx)');
ok($forward_data[2] eq 'push	%ebp');
ok($forward_data[3] eq 'mov	%esp, %ebp');
ok($forward_data[4] eq 'push	%ecx');
