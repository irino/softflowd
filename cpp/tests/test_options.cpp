// The numbers of the command line (D34): the whole argument is a decimal number, as in the C
// version, where atoi () read "5x" as 5 and "abc" as 0.
#include <cassert>
#include <climits>
#include <cstdio>

#include "softflowd_cpp/options.hpp"

using namespace softflowd_cpp;

namespace {

bool
accepted (const char *s, bool allow_minus, long long min, long long max, long long expected) {
  long long value = -12345;
  return parse_int_arg (s, allow_minus, min, max, value) && value == expected;
}

bool
refused (const char *s, bool allow_minus, long long min, long long max) {
  long long value = -12345;
  return !parse_int_arg (s, allow_minus, min, max, value) && value == -12345;
}

void
test_a_whole_decimal_number_is_taken () {
  assert (accepted ("5", false, 0, 100, 5));
  assert (accepted ("+5", false, 0, 100, 5));
  assert (accepted ("007", false, 0, 100, 7));
  assert (accepted ("0", false, 0, 100, 0));
  assert (accepted ("100", false, 0, 100, 100));
  assert (accepted ("4294967295", false, 0, 4294967295LL, 4294967295LL));
  // -L takes "-0": a '-' is allowed, and the range decides.
  assert (accepted ("-0", true, 0, 255, 0));
  assert (accepted ("-3", true, -10, 255, -3));
}

void
test_anything_else_is_refused () {
  assert (refused ("", false, 0, 100));
  assert (refused ("5x", false, 0, 100));
  assert (refused ("abc", false, 0, 100));
  assert (refused (" 5", false, 0, 100));
  assert (refused ("5 ", false, 0, 100));
  assert (refused ("5.0", false, 0, 100));
  assert (refused ("0x10", false, 0, 100));
  assert (refused ("+", false, 0, 100));
  assert (refused ("++5", false, 0, 100));
  assert (refused ("+-5", true, 0, 100));
  // A sign that is not allowed, and a range.
  assert (refused ("-0", false, 0, 100));
  assert (refused ("-1", false, 0, 100));
  assert (refused ("-1", true, 0, 255));
  assert (refused ("101", false, 0, 100));
  assert (refused ("0", false, 1, 100));
  assert (refused ("4294967296", false, 0, 4294967295LL));
  assert (refused ("99999999999999999999", false, 0, LLONG_MAX));
}

void
test_the_version_is_a_plain_number () {
  assert (parse_netflow_version ("1") == ExportFormat::Netflow1);
  assert (parse_netflow_version ("5") == ExportFormat::Netflow5);
  assert (parse_netflow_version ("9") == ExportFormat::Netflow9);
  assert (parse_netflow_version ("10") == ExportFormat::Ipfix);
  assert (parse_netflow_version ("psamp") == ExportFormat::Psamp);
  // atoi () read "09" as 9 and "5x" as 5.
  for (const char *bad : {"09", "+5", "5x", "9x", "5.0", " 5", "abc", "", "0", "010", "99"}) {
    assert (!parse_netflow_version (bad).has_value());
  }
}

} // namespace

int
main () {
  test_a_whole_decimal_number_is_taken();
  test_anything_else_is_refused();
  test_the_version_is_a_plain_number();
  std::puts ("all option number tests passed");
  return 0;
}
