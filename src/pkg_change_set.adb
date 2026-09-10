-- SPDX-License-Identifier: BSD-3-Clause
package body Pkg_Change_Set with SPARK_Mode is
   function Valid (S : Set) return Boolean is
   begin
      if S.ID = Zero_Digest or else S.Repository = Zero_Digest or else S.Incorporation = Zero_Digest
        or else S.Policy = Zero_Digest or else S.Base_Generation = 0 or else S.Count = 0 then return False; end if;
      for I in 1 .. S.Count loop
         if S.Changes (I).Package_ID = Zero_Digest or else S.Changes (I).Contract = Zero_Digest then return False; end if;
         if S.Changes (I).Kind = Remove then
            if S.Changes (I).Is_Protected or else S.Changes (I).From_Build = Zero_Digest or else S.Changes (I).To_Build /= Zero_Digest then return False; end if;
         elsif S.Changes (I).Kind = Install then
            if S.Changes (I).From_Build /= Zero_Digest or else S.Changes (I).To_Build = Zero_Digest then return False; end if;
         elsif S.Changes (I).From_Build = Zero_Digest or else S.Changes (I).To_Build = Zero_Digest then return False; end if;
         for J in 1 .. I - 1 loop if S.Changes (I).Package_ID = S.Changes (J).Package_ID then return False; end if; end loop;
      end loop;
      return True;
   end Valid;
   function Maximum_Activation (S : Set) return Pkg_Advisory.Activation is
      Result : Pkg_Advisory.Activation := Pkg_Advisory.Immediate;
   begin
      if not Valid (S) then return Pkg_Advisory.Offline_Migration; end if;
      for I in 1 .. S.Count loop
         if Pkg_Advisory.Activation'Pos (S.Changes (I).Activation) > Pkg_Advisory.Activation'Pos (Result)
         then Result := S.Changes (I).Activation; end if;
      end loop;
      return Result;
   end Maximum_Activation;
end Pkg_Change_Set;
