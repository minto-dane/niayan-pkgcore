-- SPDX-License-Identifier: BSD-3-Clause
package body Pkg_Holds with SPARK_Mode is
   function Valid (C : Catalog) return Boolean is
   begin
      if C.Repository = Zero_Digest or else C.Policy = Zero_Digest or else C.Epoch = 0 then return False; end if;
      for I in 1 .. C.Count loop
         if not MC_Maintenance.Valid (C.Items (I)) then return False; end if;
         for J in 1 .. I - 1 loop
            if C.Items (I).Hold_ID = C.Items (J).Hold_ID then return False; end if;
         end loop;
      end loop;
      return True;
   end Valid;
   function Blocked (C : Catalog; Subject : Digest; Op : Operation; Now : Counter) return Boolean is
   begin
      if not Valid (C) or else Subject = Zero_Digest then return True; end if;
      for I in 1 .. C.Count loop
         if (C.Items (I).Expires_At = 0 or else Now < C.Items (I).Expires_At)
           and then MC_Maintenance.Blocks
             (C.Items (I), Subject, Op = Apply, Op = Accept_Change, Op = Commit)
         then return True; end if;
      end loop;
      return False;
   end Blocked;
end Pkg_Holds;
