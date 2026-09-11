-- SPDX-License-Identifier: BSD-3-Clause
with Pkg_Configured_Root; with Pkg_Generation_Intent; with MC_Text;
package body Pkg_Generation_Configuration with SPARK_Mode => Off is
   use type Pkg_Generation_Manifest.Format_Kind;
   procedure Unavailable (Generation : Digest; Root_ID, Transaction_ID : Identity;
      Context : Digest; Phase : String; Root_FD : out Integer; Status : out Outcome) is
      pragma Unreferenced (Generation, Root_ID, Transaction_ID, Context, Phase);
   begin Root_FD := -1; Status := Denied; end Unavailable;
   procedure Check_Current (Store : in out MC_Store.Store;
      M : Pkg_Generation_Manifest.Manifest; Root_FD : Integer;
      Deadline : Counter; Status : out Outcome) is
      Root_ID : Identity; Native_Architecture : MC_Text.Value; Archive : Digest;
   begin
      Status := Invalid_Input;
      if not Pkg_Generation_Manifest.Valid (M) or else M.Format /= Pkg_Generation_Manifest.Configured_V6 then return; end if;
      Status := Denied; if Root_FD < 0 then return; end if;
      Pkg_Generation_Intent.Read_Target_Scope (Store, M.Intent, M.Catalog, M.Catalog_Closure,
         Deadline, Root_ID, Native_Architecture, Status);
      if Status = OK then
         Pkg_Configured_Root.Verify_Current (Store, Root_FD, M.Configured_Root, M.Configuration_Closure,
            M.Root_Archive, M.Catalog, M.Catalog_Closure, Root_ID, M.Transaction_ID, M.Intent,
            MC_Text.Image (Native_Architecture), MC_Store.Max_Object_Size, Deadline, Archive, Status);
      end if;
   exception when Storage_Error => Status := Exhausted; when others => Status := Indeterminate;
   end Check_Current;
end Pkg_Generation_Configuration;
