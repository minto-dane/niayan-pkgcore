-- SPDX-License-Identifier: BSD-3-Clause
with Ada.Unchecked_Deallocation; with MC_Atomic;
package body Pkg_Generation_Storage with SPARK_Mode => Off is
   package GD renames Pkg_Generation_Descriptor;
   package GM renames Pkg_Generation_Manifest;
   type Buffer_Access is access Bytes;
   procedure Free is new Ada.Unchecked_Deallocation (Bytes, Buffer_Access);
   procedure Read_State (Root, State : MC_FS.Root; Expected_Root : Identity;
      RS : out Pkg_Root_State.State; Status : out Outcome) is
      Frame : Pkg_Root_State.Frame; Marker : Bytes (1 .. 16); Used : Natural;
   begin
      RS := (others => <>); MC_Atomic.Read (Root, ".mission/root.id", Marker, Used, Status);
      if Status = OK and then (Used /= 16 or else Marker /= Expected_Root) then Status := Denied; end if;
      if Status = OK then MC_Atomic.Read (State, "root.state", Frame, Used, Status); end if;
      if Status = OK and then Used /= Frame'Length then Status := Corrupt; end if;
      if Status = OK then Pkg_Root_State.Decode (Frame, RS, Status); end if;
      if Status = OK and then RS.Root_ID /= Expected_Root then Status := Denied; end if;
      if Status = OK and then RS.Generation = 0
        and then (RS.Accepted_Plan /= Zero_Digest or else RS.Package_Set /= Zero_Digest)
      then Status := Corrupt; end if;
   end Read_State;
   procedure Read_Plan (Store : MC_Store.Store; Hash : Digest; P : out Pkg_File_Plan.Plan; Status : out Outcome) is
      B : Buffer_Access := new Bytes (1 .. Pkg_File_Plan.Max_Plan_Bytes); Used : Natural;
   begin
      MC_Store.Read_Object (Store, Hash, B.all, Used, Status);
      if Status = OK then Pkg_File_Plan.Decode (B (1 .. Used), P, Status); end if;
      Free (B);
   exception when others => Free (B); Status := Indeterminate;
   end Read_Plan;
   procedure Read_Manifest (Store : MC_Store.Store; D : GD.Descriptor; M : out GM.Manifest; Status : out Outcome) is
      B : Bytes (1 .. GM.Max_Bytes); Used : Natural;
   begin
      M := (others => <>); MC_Store.Read_Object (Store, D.Manifest, B, Used, Status);
      if Status = OK then GM.Decode (B (1 .. Used), M, Status); end if;
      if Status = OK and then (M.Stage_ID /= D.Stage_ID or else M.Catalog /= D.Catalog) then Status := Conflict; end if;
      if Status = OK then MC_Store.Check_Pin (Store, M.Transaction_ID, D.Manifest, Status); end if;
   end Read_Manifest;
end Pkg_Generation_Storage;
