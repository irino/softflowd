// The numbers of the command line (D34): the whole argument is a decimal number, as in the C
// version, where atoi () read "5x" as 5 and "abc" as 0.
#include <array>
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

bool
mac_is (const char *s, std::array<std::uint8_t, 6> expected) {
  std::array<std::uint8_t, 6> mac{};
  return parse_mac_address (s, mac) && mac == expected;
}

void
test_the_mac_address_is_six_groups_with_colons () {
  // The same inputs and answers as the C version (./softflowd -r FILE -H MAC).
  assert (mac_is ("02:00:00:00:00:01", {0x02, 0, 0, 0, 0, 0x01}));
  assert (mac_is ("AA:BB:CC:DD:EE:FF", {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}));
  assert (mac_is ("aa:Bb:cC:dD:eE:Ff", {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}));
  assert (mac_is ("1:2:3:4:5:6", {1, 2, 3, 4, 5, 6}));
  assert (mac_is ("02:00:00:00:00:0", {2, 0, 0, 0, 0, 0}));
  for (const char *bad :
       {"02-00-00-00-00-01", "1-2-3-4-5-6", "aa:bb-cc:dd-ee:ff", "aa:bb:cc:dd:ee",
        "aa:bb:cc:dd:ee:ff:00", "aa:bb:cc:dd:ee:ff:gg", "aa:bb:cc:dd:ee:ff-",
        "aa:bb:cc:dd:ee:ff:", "aa:bb:cc:dd:ee:ff ", " 2:00:00:00:00:01",
        "002:00:00:00:00:01", "0x2:00:00:00:00:01", "+2:00:00:00:00:01",
        "-2:00:00:00:00:01", "02:00:00:00:00:", ":00:00:00:00:01", "::::::",
        "g2:00:00:00:00:01", "02.00.00.00.00.01", "020000000001", ""}) {
    std::array<std::uint8_t, 6> mac{9, 9, 9, 9, 9, 9};
    assert (!parse_mac_address (bad, mac));
    assert (mac == (std::array<std::uint8_t, 6>{9, 9, 9, 9, 9, 9})); // not changed
  }
}

void
test_the_interface_index_is_a_plain_number () {
  // The answers of ./softflowd -D -i SPEC ("Using lo (idx: N)").
  assert (parse_ifindex ("3") == 3);
  assert (parse_ifindex ("+3") == 3);
  assert (parse_ifindex ("0") == 0);
  assert (parse_ifindex ("007") == 7);
  assert (parse_ifindex ("65535") == 65535);
  assert (parse_ifindex ("00000000000000000000007") == 7);
  for (const char *none : {"", "+", "abc", "65536", "70000", "99999999999", "-1", "3x", " 3"}) {
    assert (parse_ifindex (none) == 0);
  }
}

} // namespace

int
main () {
  test_a_whole_decimal_number_is_taken();
  test_anything_else_is_refused();
  test_the_version_is_a_plain_number();
  test_the_mac_address_is_six_groups_with_colons();
  test_the_interface_index_is_a_plain_number();
  std::puts ("all option number tests passed");
  return 0;
}
