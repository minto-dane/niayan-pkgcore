-- SPDX-License-Identifier: MIT
package body Pkg_Maintenance_Bundle with SPARK_Mode is
   function Valid (B : Bundle) return Boolean is
   begin
      if B.ID=Zero_Digest or else B.Repository=Zero_Digest or else B.Policy=Zero_Digest
        or else B.Baseline=Zero_Digest or else B.Epoch=0 or else B.Security_Epoch=0
        or else B.Count=0 or else not B.Signed or else B.Withdrawn then return False; end if;
      for N in 1..B.Count loop
         if B.Content(N).Package_ID=Zero_Digest or else B.Content(N).Required_Build=Zero_Digest
           or else B.Content(N).Advisory=Zero_Digest then return False; end if;
         for M in 1..N-1 loop if B.Content(M).Package_ID=B.Content(N).Package_ID then return False; end if; end loop;
      end loop;
      return True;
   end Valid;
   function Satisfied (B : Bundle; I : Inventory; Count : Natural) return Boolean is
      Found : Boolean;
   begin
      if not Valid(B) or else Count>I'Length then return False; end if;
      for N in 1..B.Count loop
         if B.Content(N).Required then
            Found:=False;
            for M in 1..Count loop
               if I(M).Package_ID=B.Content(N).Package_ID and then I(M).Build=B.Content(N).Required_Build then Found:=True; end if;
            end loop;
            if not Found then return False; end if;
         end if;
      end loop;
      return True;
   end Satisfied;
end Pkg_Maintenance_Bundle;
