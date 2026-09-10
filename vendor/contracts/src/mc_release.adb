-- SPDX-License-Identifier: BSD-3-Clause
package body MC_Release with SPARK_Mode is
   function Qualified (Evidence : Evidence_Set) return Boolean is
   begin
      for Item in Evidence'Range loop
         if Evidence (Item) /= Passed then return False; end if;
         pragma Loop_Invariant
           (for all J in Evidence'First .. Item => Evidence (J) = Passed);
      end loop;
      return True;
   end Qualified;
end MC_Release;
