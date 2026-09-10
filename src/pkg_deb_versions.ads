-- SPDX-License-Identifier: BSD-3-Clause
-- Debian epoch/upstream/revision order. Independent of libsolv and RPM order.
package Pkg_Deb_Versions with SPARK_Mode, Pure is
   Max_Length : constant := 512;
   type Ordering is (Older, Equal, Newer);
   function Valid (Text : String) return Boolean
     with Global => null;
   function Compare (Left, Right : String) return Ordering
     with Global => null,
          Pre => Valid (Left) and then Valid (Right);
   -- Supported epoch range is 0 .. 2**31-1. Reject malformed/unsupported versions
   -- before Compare. In particular RPM '^' and DEB '~' are not interchangeable.
   -- Contracts are proof obligations; this source release has NOT run GNATprove.
end Pkg_Deb_Versions;
