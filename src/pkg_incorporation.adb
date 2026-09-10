-- SPDX-License-Identifier: BSD-3-Clause
package body Pkg_Incorporation with SPARK_Mode is
   function Valid (I : Incorporation) return Boolean is
   begin
      if I.ID = Zero_Digest or else I.Policy = Zero_Digest or else I.Repository = Zero_Digest
        or else I.Epoch = 0 or else I.Count = 0 then return False; end if;
      for J in 1 .. I.Count loop
         if I.Items (J).Name = Zero_Digest or else I.Items (J).EVR = Zero_Digest
           or else I.Items (J).Package_Digest = Zero_Digest then return False; end if;
         for K in 1 .. J - 1 loop
            if I.Items (J).Name = I.Items (K).Name then return False; end if;
         end loop;
      end loop;
      return True;
   end Valid;
   function Satisfied (I : Incorporation; Installed : Inventory; Installed_Count : Natural) return Boolean is
      Found : Boolean;
   begin
      if not Valid (I) or else Installed_Count > Max_Members then return False; end if;
      for J in 1 .. I.Count loop
         Found := False;
         for K in 1 .. Installed_Count loop
            if Installed (K).Name = I.Items (J).Name then
               if Installed (K).EVR /= I.Items (J).EVR
                 or else Installed (K).Package_Digest /= I.Items (J).Package_Digest
               then return False; end if;
               Found := True;
            end if;
         end loop;
         if I.Items (J).Required and then not Found then return False; end if;
      end loop;
      return True;
   end Satisfied;
end Pkg_Incorporation;
