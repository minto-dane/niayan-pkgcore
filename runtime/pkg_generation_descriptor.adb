-- SPDX-License-Identifier: BSD-3-Clause
with MC_Codec; with MC_Hex; with MC_SHA256; with MC_Text;
package body Pkg_Generation_Descriptor with SPARK_Mode => Off is
   use type Byte; use type Wide; use type Word; use type Pkg_File_Plan.Shape;
   use type Pkg_File_Plan.Kind; use type Pkg_File_Plan.State_Domain;
   Magic : constant Bytes := (78, 73, 65, 80, 85, 66, 48, 49);
   function Valid (D : Descriptor) return Boolean is
     (D.Root_ID /= Zero_Identity and then D.Stage_ID /= Zero_Identity and then D.Root_ID /= D.Stage_ID
      and then D.Manifest /= Zero_Digest and then D.Catalog /= Zero_Digest and then D.Generation > 0
      and then ((D.Generation = 1) = (D.Previous = Zero_Digest)));
   function Encode (D : Descriptor) return Frame is
      B : Frame := (others => 0);
   begin
      if not Valid (D) then return B; end if;
      B (1 .. 8) := Magic; B (9 .. 24) := D.Root_ID; B (25 .. 40) := D.Stage_ID;
      B (41 .. 72) := D.Manifest; B (73 .. 104) := D.Catalog;
      MC_Codec.Put64 (B, 105, Wide (D.Generation)); B (113 .. 144) := D.Previous;
      B (161 .. 192) := MC_SHA256.Hash (B (1 .. 160)); return B;
   end Encode;
   procedure Decode (B : Bytes; D : out Descriptor; Status : out Outcome) is
      Candidate : Descriptor;
   begin
      D := Empty; Status := Corrupt;
      if B'First /= 1 or else B'Length /= Frame'Length or else B (1 .. 8) /= Magic
        or else B (161 .. 192) /= MC_SHA256.Hash (B (1 .. 160))
        or else MC_Codec.U64 (B, 105) > Wide (Counter'Last) then return; end if;
      for I in 145 .. 160 loop if B (I) /= 0 then return; end if; end loop;
      Candidate := (B (9 .. 24), B (25 .. 40), B (41 .. 72), B (73 .. 104),
                    Counter (MC_Codec.U64 (B, 105)), B (113 .. 144));
      if not Valid (Candidate) then return; end if;
      D := Candidate; Status := OK;
   end Decode;
   procedure Load (Store : MC_Store.Store; Hash : Digest; D : out Descriptor; Status : out Outcome) is
      B : Bytes (1 .. Frame'Length + 1); Used : Natural;
   begin
      D := Empty; MC_Store.Read_Object (Store, Hash, B, Used, Status);
      if Status = OK then Decode (B (1 .. Used), D, Status); end if;
   end Load;
   function Shape (D : Descriptor; UID, GID : Word) return Pkg_File_Plan.Shape is
     (if D = Empty then (others => <>) else
      (Node_Kind => Pkg_File_Plan.Regular, Mode => 8#400#, UID => UID, GID => GID,
       Size => Frame'Length, Content => MC_SHA256.Hash (Encode (D)),
       Xattrs => MC_SHA256.Hash (Bytes'(0, 0)), others => <>));
   procedure Compile (Before, After : Descriptor; Transaction_ID : Identity;
      Epoch, Fence : Counter; Effect_Contract : Digest; UID, GID : Word;
      P : out Pkg_File_Plan.Plan; Status : out Outcome) is
   begin
      Pkg_File_Plan.Clear (P); Status := Invalid_Input;
      if not Valid (After) or else Transaction_ID = Zero_Identity or else Epoch = 0 or else Fence = 0
        or else Effect_Contract = Zero_Digest then return; end if;
      if After.Generation = 1 then
         if Before /= Empty then return; end if;
      elsif not Valid (Before) or else Before.Generation = Counter'Last
        or else After.Generation /= Before.Generation + 1 or else After.Root_ID /= Before.Root_ID
        or else After.Stage_ID = Before.Stage_ID or else After.Previous /= MC_SHA256.Hash (Encode (Before))
      then return; end if;
      P.Root_ID := After.Root_ID; P.Transaction_ID := Transaction_ID;
      P.Base_Generation := After.Generation - 1; P.Target_Generation := After.Generation;
      P.Epoch := Epoch; P.Fence := Fence; P.Package_Set := After.Catalog; P.Effect_Contract := Effect_Contract;
      P.Count := 1; MC_Text.Set (P.Changes (1).Path, "generation.next", Status);
      if Status /= OK then return; end if;
      P.Changes (1).Before := Shape (Before, UID, GID); P.Changes (1).After := Shape (After, UID, GID);
      if not Pkg_File_Plan.Layout_Valid (P) then Status := Invalid_Input; end if;
   end Compile;
   procedure Check (Store : MC_Store.Store; P : Pkg_File_Plan.Plan;
      Before, After : out Descriptor; Status : out Outcome) is
      C : Pkg_File_Plan.Change renames P.Changes (1);
   begin
      Before := Empty; After := Empty; Status := Denied;
      if not Pkg_File_Plan.Layout_Valid (P) or else P.Count /= 1
        or else MC_Text.Image (C.Path) /= "generation.next" or else C.Domain /= Pkg_File_Plan.Packaged_Files
        or else C.After.Node_Kind /= Pkg_File_Plan.Regular then return; end if;
      Load (Store, C.After.Content, After, Status); if Status /= OK then return; end if;
      if P.Base_Generation /= 0 then
         Load (Store, C.Before.Content, Before, Status); if Status /= OK then return; end if;
      end if;
      Status := Denied;
      if After.Root_ID /= P.Root_ID or else After.Generation /= P.Target_Generation or else After.Catalog /= P.Package_Set
        or else C.After /= Shape (After, C.After.UID, C.After.GID)
        or else C.Before /= Shape (Before, C.After.UID, C.After.GID) then return; end if;
      if P.Base_Generation /= 0 and then (Before.Root_ID /= After.Root_ID
        or else Before.Stage_ID = After.Stage_ID or else Before.Generation /= P.Base_Generation
        or else After.Previous /= MC_SHA256.Hash (Encode (Before))) then return; end if;
      Status := OK;
   end Check;
   function Stage_Path (Bank : String; D : Descriptor) return String is
     (Bank & "/" & MC_Hex.Encode (D.Stage_ID));
end Pkg_Generation_Descriptor;
