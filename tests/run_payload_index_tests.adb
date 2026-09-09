-- SPDX-License-Identifier: MIT
with Ada.Command_Line; with Ada.Directories; with Ada.Text_IO;
with Ada.Strings.Unbounded; with Interfaces.C;
with MC_Types; use MC_Types;
with MC_Clock; with MC_FS; with MC_Hex; with MC_Posix; with MC_Runtime; with MC_Store;
with Pkg_Deb_Payload; with Pkg_Payload_Index;
with Test_Support; use Test_Support;
procedure Run_Payload_Index_Tests with SPARK_Mode => Off is
   package P renames Pkg_Deb_Payload; package X renames Pkg_Payload_Index;
   use Ada.Strings.Unbounded;
   use type X.Package_Source; use type Interfaces.C.unsigned; use type P.Entry_Kind; use type P.Payload_Entry; use type Word;
   Store : MC_Store.Store; Media, Extra : MC_FS.Root; Status : Outcome;
   Original : Digest; Now, Deadline : Counter;
   Value, Other : X.Index; Empty : P.Inventory;
   Sources : array (1 .. 14) of P.Inventory;
   Names : constant array (1 .. 14) of Unbounded_String :=
     (To_Unbounded_String ("basic.deb"), To_Unbounded_String ("empty.deb"),
      To_Unbounded_String ("gnu.deb"), To_Unbounded_String ("pax.deb"),
      To_Unbounded_String ("unicode.deb"), To_Unbounded_String ("multilingual.deb"),
      To_Unbounded_String ("gnu-numeric.deb"), To_Unbounded_String ("flags.deb"),
      To_Unbounded_String ("attributes.deb"), To_Unbounded_String ("negative-clock.deb"),
      To_Unbounded_String ("negative-zero.deb"), To_Unbounded_String ("overlap.deb"),
      To_Unbounded_String ("shared.deb"), To_Unbounded_String ("links.deb"));
   Item, Base, Old : X.Claim; Expected : P.Payload_Entry; Source : X.Package_Source;
   State : X.Path_State; Hash : Digest;
   procedure Need (Label_Text : String) is
   begin Expect (Status = OK, Label_Text & Outcome'Image (Status)); end Need;
   procedure Load (Root : MC_FS.Root; Name : String; Result : in out P.Inventory) is
      F : MC_FS.File;
   begin
      MC_FS.Open_Read (Root, Name, F, Status); Need ("source open " & Name);
      MC_Store.Import_File (Store, F, MC_Store.Max_Object_Size, Original, Status); Need ("source import");
      MC_FS.Close (F); P.Stage (Store, Original, Deadline, Result, Status); Need ("native payload " & Name);
   exception when others => MC_FS.Close (F); raise;
   end Load;
   procedure Hidden (Index : X.Index) is
   begin
      Expect (not X.Sealed (Index) and then X.Fingerprint (Index) = Zero_Digest
         and then X.Package_Count (Index) = 0 and then X.Claim_Count (Index) = 0
         and then X.Path_Count (Index) = 0, "no partial source/claim publication");
      X.Read_Claim (Index, 1, Item, Status);
      Expect (Status = Invalid_Input and then Item.Source.Original = Zero_Digest, "hidden claim reset");
   end Hidden;
   procedure Inspect (Path : String; Count : Natural) is
   begin
      X.Inspect_Path (Value, Path, State, Status); Need ("inspect path " & Path);
      Expect ((if Count = 0 then State.First = 0 and then State.Last = 0
               else State.First > 0 and then State.Last - State.First + 1 = Count), "all path claims visible");
   end Inspect;
   procedure Print_Index (Index : X.Index) is
   begin
      Ada.Text_IO.Put_Line ("INDEX " & MC_Hex.Encode (X.Fingerprint (Index)));
      Ada.Text_IO.Put_Line ("PACKAGES" & Natural'Image (X.Package_Count (Index)));
      Ada.Text_IO.Put_Line ("CLAIMS" & Natural'Image (X.Claim_Count (Index)));
      Ada.Text_IO.Put_Line ("PATHS" & Natural'Image (X.Path_Count (Index)));
   end Print_Index;
begin
   Expect (Ada.Command_Line.Argument_Count in 3 | 4, "fresh CAS, payload fixtures and index fixtures or scan list");
   MC_Runtime.Initialize (Status); Need ("runtime");
   if MC_Posix.Euid = 0 then
      X.Add (Value, Empty, 0, Status); Expect (Status = Denied, "root Add refused before access");
      X.Seal (Value, 0, Status); Expect (Status = Denied, "root Seal refused before access"); Hidden (Value); Report; return;
   end if;
   MC_Store.Initialize (Ada.Command_Line.Argument (1), Store, Status); Need ("private CAS");
   MC_FS.Open_Root (Ada.Directories.Full_Name (Ada.Command_Line.Argument (2)), Media, Status); Need ("source root");
   MC_Clock.Boottime_Milliseconds (Now, Status); Need ("clock"); Deadline := Now + 300_000;
   if Ada.Command_Line.Argument_Count = 4 then
      Expect (Ada.Command_Line.Argument (4) = "--scan", "exact observation mode");
      declare List : Ada.Text_IO.File_Type; Name : String (1 .. 4096); Last : Natural; begin
         Ada.Text_IO.Open (List, Ada.Text_IO.In_File, Ada.Command_Line.Argument (3));
         while not Ada.Text_IO.End_Of_File (List) loop
            Ada.Text_IO.Get_Line (List, Name, Last); Expect (Last in 1 .. 4095, "bounded source basename");
            Load (Media, Name (1 .. Last), Empty); X.Add (Value, Empty, Deadline, Status); Need ("add scanned source"); P.Clear (Empty);
         end loop;
         Ada.Text_IO.Close (List);
      end;
      X.Seal (Value, Deadline, Status); Need ("seal scanned source set"); Print_Index (Value);
      MC_FS.Close (Media); MC_Store.Close (Store); Report; return;
   end if;
   MC_FS.Open_Root (Ada.Directories.Full_Name (Ada.Command_Line.Argument (3)), Extra, Status); Need ("additional source root");
   Hidden (Value); X.Seal (Value, Deadline, Status); Expect (Status = Invalid_Input, "empty collection not sealed");
   X.Add (Value, Empty, Deadline, Status); Expect (Status = Invalid_Input, "unobserved source refused"); Hidden (Value);
   for I in Sources'Range loop
      if I <= 11 then Load (Media, To_String (Names (I)), Sources (I));
      else Load (Extra, To_String (Names (I)), Sources (I)); end if;
      X.Add (Value, Sources (I), Deadline, Status); Need ("add complete source"); Hidden (Value);
   end loop;
   X.Seal (Value, Deadline, Status); Need ("complete source index");
   Expect (X.Sealed (Value) and then X.Package_Count (Value) = 14 and then X.Claim_Count (Value) = 35, "all sources and claims preserved");
   Hash := X.Fingerprint (Value); Expect (Hash /= Zero_Digest, "source index hash"); Print_Index (Value);
   X.Seal (Value, Deadline, Status); Need ("idempotent seal"); Expect (X.Fingerprint (Value) = Hash, "idempotent fingerprint");
   for I in reverse Sources'Range loop X.Add (Other, Sources (I), Deadline, Status); Need ("reverse source order"); end loop;
   X.Seal (Other, Deadline, Status); Need ("reverse seal");
   Expect (X.Fingerprint (Other) = Hash and then X.Path_Count (Other) = X.Path_Count (Value), "input order does not choose ownership");
   for I in 1 .. X.Package_Count (Value) loop
      X.Read_Package (Value, I, Source, Status); Need ("ordered source");
      if I > 1 then Expect (MC_Hex.Encode (Old.Source.Original) < MC_Hex.Encode (Source.Original), "canonical source order"); end if;
      Old.Source := Source;
   end loop;
   for I in 1 .. X.Claim_Count (Value) loop
      X.Read_Claim (Value, I, Item, Status); Need ("claim read");
      X.Read_Claim (Other, I, Base, Status); Need ("reverse claim read");
      Expect (Item.Source = Base.Source and then Item.Source_Position = Base.Source_Position
         and then Item.Item = Base.Item, "stable order and attributes");
      declare Found : Boolean := False; begin
         for J in Sources'Range loop
            if P.Original_Hash (Sources (J)) = Item.Source.Original then
               Found := True; P.Read_Entry (Sources (J), Item.Source_Position, Expected, Status); Need ("source entry lookup");
               Expect (Item.Source.Tar = P.Tar_Hash (Sources (J)) and then Item.Source.Entries = P.Count (Sources (J))
                  and then Item.Item = Expected, "complete source and metadata identity");
            end if;
         end loop;
         Expect (Found, "claim owner retained");
      end;
      if I > 1 then
         Expect (P.Byte_Strings.To_String (Old.Item.Path) <= P.Byte_Strings.To_String (Item.Item.Path), "raw byte path order");
      end if;
      Old := Item;
   end loop;
   Inspect ("usr", 3); Expect (State.All_Directories and then not State.Same_Inode_Attributes
      and then not State.Parent_Missing and then not State.Non_Directory_Ancestor, "shared directory differences remain explicit");
   Inspect ("empty", 2); Expect (not State.All_Directories and then State.Same_Inode_Attributes, "identical non-directory still has two owners");
   Inspect ("usr/a", 2); Expect (not State.All_Directories and then not State.Same_Inode_Attributes, "different content has no last-writer selection");
   Inspect ("absolute/child", 1); Expect (State.Non_Directory_Ancestor and then not State.Parent_Missing, "cross-source link ancestor remains unresolved");
   Inspect ("資料/更新.txt", 1); Expect (State.Parent_Missing, "implicit parent has no invented attributes");
   Inspect ("distinct-é", 1); Inspect ("distinct-é", 1);
   Inspect ("missing", 0); Inspect ("", 1);
   Inspect ("alias", 1); X.Read_Claim (Value, State.First, Item, Status); Need ("hardlink header");
   X.Read_Inode (Value, State.First, Base, Status); Need ("hardlink inode");
   Expect (Item.Item.Values.Kind = P.Hard_Link and then Item.Item.Values.Mode = 8#600#
      and then Base.Item.Values.Kind = P.Regular and then Base.Item.Values.Mode = 8#6755#
      and then Base.Source.Original = Item.Source.Original and then Base.Source_Position = 2,
      "header and inode metadata remain separate");
   Inspect ("forward", 1); X.Read_Inode (Value, State.First, Base, Status); Need ("forward source inode");
   Expect (Base.Source.Original = P.Original_Hash (Sources (1)) and then Base.Source_Position = 3
      and then Base.Item.Values.Mode = 8#6751#, "overlapping path cannot retarget package-local hardlink");
   X.Read_Claim (Value, X.Claim_Count (Value) + 1, Item, Status);
   Expect (Status = Invalid_Input and then Item.Source.Original = Zero_Digest, "claim bounds reset");
   X.Read_Inode (Value, X.Claim_Count (Value) + 1, Item, Status); Expect (Status = Invalid_Input, "inode bounds");
   X.Read_Package (Value, X.Package_Count (Value) + 1, Source, Status);
   Expect (Status = Invalid_Input and then Source.Original = Zero_Digest, "source bounds reset");
   X.Add (Other, Sources (1), Deadline, Status); Expect (Status = Invalid_Input, "sealed collection cannot be appended"); Hidden (Other);
   X.Add (Other, Sources (1), Deadline, Status); Need ("new collection");
   X.Add (Other, Sources (1), Deadline, Status); Expect (Status = Conflict, "duplicate original is not silently deduplicated"); Hidden (Other);
   X.Add (Other, Sources (2), Deadline, Status); Need ("empty original source");
   X.Seal (Other, Deadline, Status); Need ("seal empty payload source");
   Expect (X.Package_Count (Other) = 1 and then X.Claim_Count (Other) = 0 and then X.Path_Count (Other) = 0
      and then X.Fingerprint (Other) /= Zero_Digest, "empty package retained in source set");
   X.Inspect_Path (Other, "", State, Status); Need ("empty source namespace"); Expect (State.First = 0, "no invented root");
   X.Seal (Other, 0, Status); Expect (Status = Stale, "expired seal clears candidate"); Hidden (Other);
   X.Add (Other, Sources (1), Deadline, Status); Need ("restart after expiry");
   X.Add (Other, Sources (2), 0, Status); Expect (Status = Stale, "expired addition cannot admit prior subset"); Hidden (Other);
   for I in Sources'Range loop P.Clear (Sources (I)); end loop;
   Expect (X.Fingerprint (Value) = Hash and then X.Claim_Count (Value) = 35, "source lifetime cannot mutate sealed index");
   Inspect ("alias", 1); X.Read_Inode (Value, State.First, Base, Status); Need ("owned copy after source clear");
   Expect (Base.Item.Values.Mode = 8#6755#, "inode metadata remains owned by index");
   X.Clear (Value); X.Clear (Value); Hidden (Value);
   MC_FS.Close (Media); MC_FS.Close (Extra); MC_Store.Close (Store); Report;
exception when others => MC_FS.Close (Media); MC_FS.Close (Extra); MC_Store.Close (Store); raise;
end Run_Payload_Index_Tests;
