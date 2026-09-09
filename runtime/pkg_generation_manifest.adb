-- SPDX-License-Identifier: MIT
with Ada.Unchecked_Deallocation;
with Pkg_Catalog_Retention;
with MC_Codec; with MC_FS; with MC_SHA256; with MC_Text;
package body Pkg_Generation_Manifest with SPARK_Mode => Off is
   use type Byte; use type Word; use type Wide;
   use type Pkg_File_Plan.Kind; use type Pkg_File_Plan.State_Domain;
   subtype Magic_Bytes is Bytes (1 .. 8);
   function Magic (Format : Format_Kind) return Magic_Bytes is
     (78, 73, 65, 71, 69, 78, 48, (if Format = Structural_V1 then 49 else 50));
   function Valid (M : Manifest) return Boolean is
   begin
      if (M.Format = Structural_V1 and then M.Catalog_Closure /= Zero_Digest)
        or else (M.Format = Native_V2 and then M.Catalog_Closure = Zero_Digest)
        or else M.Stage_ID = Zero_Identity or else M.Transaction_ID = Zero_Identity
        or else M.Stage_ID = M.Transaction_ID or else M.Epoch = 0 or else M.Fence = 0
        or else M.Catalog = Zero_Digest or else M.Effect_Contract = Zero_Digest
        or else M.Count = 0 or else M.Entries < 3
        or else M.Entries < M.Count or else M.Entries > M.Count * Pkg_File_Plan.Max_Changes
      then return False; end if;
      for I in 1 .. M.Count loop
         if M.Batches (I).Plan = Zero_Digest or else M.Batches (I).Receipt = Zero_Digest then return False; end if;
         for J in 1 .. I - 1 loop
            if M.Batches (I).Plan = M.Batches (J).Plan then return False; end if;
         end loop;
      end loop;
      return True;
   end Valid;
   procedure Encode (M : Manifest; B : out Bytes; Used : out Natural; Status : out Outcome) is
      Pos : Natural := Header_Size;
   begin
      B := (others => 0); Used := 0; Status := Invalid_Input;
      if B'First /= 1 or else not Valid (M) then return; end if;
      if B'Length < Header_Size + M.Count * 64 then Status := Exhausted; return; end if;
      B (1 .. 8) := Magic (M.Format); B (9 .. 24) := M.Stage_ID; B (25 .. 40) := M.Transaction_ID;
      MC_Codec.Put64 (B, 41, Wide (M.Epoch)); MC_Codec.Put64 (B, 49, Wide (M.Fence));
      B (57 .. 88) := M.Catalog; B (89 .. 120) := M.Effect_Contract;
      if M.Format = Native_V2 then B (129 .. 160) := M.Catalog_Closure; end if;
      MC_Codec.Put32 (B, 121, Word (M.Entries)); MC_Codec.Put32 (B, 125, Word (M.Count));
      for I in 1 .. M.Count loop
         B (Pos + 1 .. Pos + 32) := M.Batches (I).Plan;
         B (Pos + 33 .. Pos + 64) := M.Batches (I).Receipt; Pos := Pos + 64;
      end loop;
      Used := Pos; Status := OK;
   end Encode;
   procedure Decode (B : Bytes; M : out Manifest; Status : out Outcome) is
      Pos : Natural := Header_Size; Candidate : Manifest;
   begin
      M := (others => <>); Status := Invalid_Input;
      if B'First /= 1 or else B'Length < Header_Size or else B'Length > Max_Bytes then return; end if;
      if B (1 .. 8) = Magic (Structural_V1) then
         for I in 129 .. Header_Size loop if B (I) /= 0 then return; end if; end loop;
      elsif B (1 .. 8) = Magic (Native_V2) then
         Candidate.Format := Native_V2; Candidate.Catalog_Closure := B (129 .. 160);
      else Status := Unsupported; return; end if;
      if MC_Codec.U64 (B, 41) > Wide (Counter'Last) or else MC_Codec.U64 (B, 49) > Wide (Counter'Last)
        or else MC_Codec.U32 (B, 121) > Word (Max_Entries)
        or else MC_Codec.U32 (B, 125) > Word (Max_Batches) then return; end if;
      Candidate.Stage_ID := B (9 .. 24); Candidate.Transaction_ID := B (25 .. 40);
      Candidate.Epoch := Counter (MC_Codec.U64 (B, 41)); Candidate.Fence := Counter (MC_Codec.U64 (B, 49));
      Candidate.Catalog := B (57 .. 88); Candidate.Effect_Contract := B (89 .. 120);
      Candidate.Entries := Natural (MC_Codec.U32 (B, 121)); Candidate.Count := Natural (MC_Codec.U32 (B, 125));
      if B'Length /= Header_Size + Candidate.Count * 64 then return; end if;
      for I in 1 .. Candidate.Count loop
         Candidate.Batches (I).Plan := B (Pos + 1 .. Pos + 32);
         Candidate.Batches (I).Receipt := B (Pos + 33 .. Pos + 64); Pos := Pos + 64;
      end loop;
      if Valid (Candidate) then M := Candidate; Status := OK; end if;
   end Decode;
   procedure Check_Retention (S : in out MC_Store.Store; M : Manifest;
                              Deadline : Counter; Status : out Outcome) is
   begin
      Status := Invalid_Input; if not Valid (M) or else Deadline = Counter'Last then return; end if;
      if M.Format /= Native_V2 then Status := Unsupported; return; end if;
      Pkg_Catalog_Retention.Verify (S, M.Catalog, M.Catalog_Closure, Deadline, Status);
   end Check_Retention;
   function Transaction (M : Manifest; Index : Positive) return Identity is
      B : Bytes (1 .. 28) := (others => 0); D : Digest;
   begin
      B (1 .. 8) := Magic (M.Format); B (9 .. 24) := M.Transaction_ID;
      MC_Codec.Put32 (B, 25, Word (Index)); D := MC_SHA256.Hash (B);
      return D (1 .. 16);
   end Transaction;
   procedure Load_Plan (S : MC_Store.Store; M : Manifest; Index : Positive;
                        P : out Pkg_File_Plan.Plan; Status : out Outcome) is
      type Buffer_Access is access Bytes;
      procedure Free is new Ada.Unchecked_Deallocation (Bytes, Buffer_Access);
      B : Buffer_Access := null; Used : Natural;
   begin
      Pkg_File_Plan.Clear (P); Status := Invalid_Input;
      if not Valid (M) or else Index > M.Count then return; end if;
      B := new Bytes (1 .. Pkg_File_Plan.Max_Plan_Bytes);
      MC_Store.Read_Object (S, M.Batches (Index).Plan, B.all, Used, Status);
      if Status = OK then Pkg_File_Plan.Decode (B (1 .. Used), P, Status); end if;
      Free (B); if Status /= OK then return; end if;
      if P.Root_ID /= M.Stage_ID or else P.Transaction_ID /= Transaction (M, Index)
        or else P.Base_Generation /= Counter (Index - 1) or else P.Target_Generation /= Counter (Index)
        or else P.Epoch /= M.Epoch or else P.Fence /= M.Fence
        or else P.Package_Set /= M.Catalog or else P.Effect_Contract /= M.Effect_Contract
      then Status := Conflict; return; end if;
      for I in 1 .. P.Count loop
         if P.Changes (I).Before.Node_Kind /= Pkg_File_Plan.Absent
           or else P.Changes (I).After.Node_Kind = Pkg_File_Plan.Absent
         then Status := Denied; return; end if;
      end loop;
   exception when others => Free (B); Status := Indeterminate;
   end Load_Plan;
   function Earlier (A, B : String) return Boolean is
      function Rank (C : Character) return Natural is
        (if C = '/' then 0 else Character'Pos (C));
   begin
      for I in 0 .. Natural'Min (A'Length, B'Length) - 1 loop
         if A (A'First + I) /= B (B'First + I) then
            return Rank (A (A'First + I)) < Rank (B (B'First + I));
         end if;
      end loop;
      return A'Length < B'Length;
   end Earlier;
   function Contained_Link (Path : String; Target : Bytes) return Boolean is
      Depth : Natural := 0; Start : Positive := Target'First;
   begin
      if Target'Length = 0 or else Target (Target'First) = 47 then return False; end if;
      for C of Path loop if C = '/' then Depth := Depth + 1; end if; end loop;
      if Depth = 0 then return False; end if;
      Depth := Depth - 1; -- tree/ is a wrapper, not an extra escape allowance.
      for I in Target'First .. Target'Last + 1 loop
         if I <= Target'Last and then (Target (I) < 32 or else Target (I) = 92) then return False; end if;
         if I = Target'Last + 1 or else Target (I) = 47 then
            if I = Start or else I - Start > 255 then return False; end if;
            declare Part : String (1 .. I - Start); begin
               for J in Part'Range loop Part (J) := Character'Val (Target (Start + J - 1)); end loop;
               if Part = ".mission" or else Part = ".mc"
                 or else (Part'Length >= 8 and then Part (1 .. 8) = ".mc-tmp-") then return False; end if;
            end;
            if I - Start = 2 and then Target (Start .. I - 1) = Bytes'(46, 46) then
               if Depth = 0 then return False; end if; Depth := Depth - 1;
            elsif I - Start = 1 and then Target (Start) = 46 then null;
            else Depth := Depth + 1; end if;
            Start := I + 1;
         end if;
      end loop;
      return True;
   end Contained_Link;
   procedure Check (S : MC_Store.Store; M : Manifest; Status : out Outcome) is
      type Plan_Access is access Pkg_File_Plan.Plan;
      procedure Free is new Ada.Unchecked_Deallocation (Pkg_File_Plan.Plan, Plan_Access);
      P : Plan_Access := null; F : MC_FS.File; V, Object_Info : MC_FS.Entry_Info;
      Link : Bytes (1 .. 4_096); Used : Natural;
      Parents : array (1 .. 64) of MC_Text.Value;
      Depth : Natural := 0; Total : Natural := 0; Previous : MC_Text.Value;
   begin
      Status := Invalid_Input; if not Valid (M) then return; end if;
      MC_Store.Open_Object (S, M.Catalog, F, Status);
      if Status = OK then MC_FS.Info (F, V, Status); end if;
      MC_FS.Close (F); if Status /= OK then return; end if;
      P := new Pkg_File_Plan.Plan;
      for I in 1 .. M.Count loop
         Load_Plan (S, M, I, P.all, Status); exit when Status /= OK;
         MC_Store.Open_Object (S, M.Batches (I).Receipt, F, Status); MC_FS.Close (F);
         exit when Status /= OK;
         for J in 1 .. P.Count loop
            declare
               C : Pkg_File_Plan.Change renames P.Changes (J);
               Path : constant String := MC_Text.Image (C.Path);
               Parent_End : Natural := 0;
            begin
               Total := Total + 1;
               if Total > M.Entries or else (Total > 1 and then not Earlier (MC_Text.Image (Previous), Path))
               then Status := Conflict; exit; end if;
               if Total = 1 then
                  if Path /= "catalog" or else C.After.Node_Kind /= Pkg_File_Plan.Regular
                    or else C.After.Content /= M.Catalog or else C.After.Size /= V.Size
                    or else C.After.Mode /= 8#400# or else C.Domain /= Pkg_File_Plan.Packaged_Files
                  then Status := Denied; exit; end if;
               elsif Total = 2 then
                  if Path /= "tree" or else C.After.Node_Kind /= Pkg_File_Plan.Directory
                    or else C.Domain /= Pkg_File_Plan.Packaged_Files then Status := Denied; exit; end if;
                  Depth := 1; Parents (1) := C.Path;
               else
                  if Path'Length <= 5 or else Path (1 .. 5) /= "tree/"
                    or else not Pkg_File_Plan.Allowed_Path (Path (6 .. Path'Last))
                  then Status := Denied; exit; end if;
                  for K in reverse Path'Range loop
                     if Path (K) = '/' then Parent_End := K - 1; exit; end if;
                  end loop;
                  while Depth > 0 and then MC_Text.Image (Parents (Depth)) /= Path (1 .. Parent_End) loop
                     Depth := Depth - 1;
                  end loop;
                  if Depth = 0 then Status := Conflict; exit; end if;
                  if C.After.Node_Kind = Pkg_File_Plan.Directory then
                     if Depth = Parents'Last then Status := Exhausted; exit; end if;
                     Depth := Depth + 1; Parents (Depth) := C.Path;
                  end if;
               end if;
               MC_Store.Open_Object (S, C.After.Xattrs, F, Status);
               if Status = OK then MC_FS.Info (F, Object_Info, Status); end if;
               MC_FS.Close (F); exit when Status /= OK;
               if Object_Info.Size > MC_FS.Max_Xattr_Bytes then Status := Exhausted; exit; end if;
               if C.After.Node_Kind /= Pkg_File_Plan.Directory then
                  MC_Store.Open_Object (S, C.After.Content, F, Status);
                  if Status = OK then MC_FS.Info (F, Object_Info, Status); end if;
                  MC_FS.Close (F); exit when Status /= OK;
                  if Object_Info.Size /= C.After.Size then Status := Corrupt; exit; end if;
                  if C.After.Node_Kind = Pkg_File_Plan.Symbolic_Link then
                     MC_Store.Read_Object (S, C.After.Content, Link, Used, Status); exit when Status /= OK;
                     if not Contained_Link (Path, Link (1 .. Used)) then Status := Denied; exit; end if;
                  end if;
               end if;
               Previous := C.Path;
            end;
         end loop;
         exit when Status /= OK;
      end loop;
      if Status = OK and then Total /= M.Entries then Status := Conflict; end if;
      Free (P);
   exception when others => Free (P); MC_FS.Close (F); Status := Indeterminate;
   end Check;
end Pkg_Generation_Manifest;
