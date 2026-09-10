-- SPDX-License-Identifier: BSD-3-Clause
package Pkg_Versions with SPARK_Mode, Pure is
   type Ordering is (Older, Equal, Newer);
   -- ASCII rpmvercmp-style VERSION/RELEASE segment comparison, including ~ and ^.
   -- Epoch is compared separately. Differential qualification against target librpm
   -- is mandatory before use as a compatibility claim.
   function Compare (Left, Right : String) return Ordering
     with Global => null,
       Pre => Left'Length <= 4_096 and then Right'Length <= 4_096
           and then Left'Last < Integer'Last and then Right'Last < Integer'Last;
end Pkg_Versions;
