-- SPDX-License-Identifier: BSD-3-Clause
with Ada.Text_IO; with Ada.Unchecked_Deallocation;
with MC_Hex;
with Pkg_Catalog_Retention; with Pkg_Catalog_Store; with Pkg_Deb_Metadata;
with Pkg_Deb_Payload; with Pkg_Payload_Index; with Pkg_Root_Archive;
with Pkg_Selected_Catalog; with Test_Support; use Test_Support;
package body Root_Archive_Order_Test is
   package A renames Pkg_Root_Archive; package C renames Pkg_Selected_Catalog;
   package X renames Pkg_Payload_Index; package P renames Pkg_Deb_Payload;
   use type P.Entry_Kind; use type Byte;
   procedure Run (Store : in out MC_Store.Store; Media : MC_FS.Root; Deadline : Counter) is
      Status : Outcome; File : MC_FS.File; Source : P.Inventory;
      Value : C.Catalog; Payload : X.Index; Packages : C.Selection (1 .. 2);
      Catalog, Closure, Manifest, Archive, Again, Owned, Legacy, Legacy_Archive : Digest;
      Limit : constant Counter := 1_048_576;
      type Observation_Access is access Pkg_Deb_Metadata.Observation;
      procedure Free is new Ada.Unchecked_Deallocation (Pkg_Deb_Metadata.Observation, Observation_Access);
      Observed : Observation_Access := new Pkg_Deb_Metadata.Observation;
      procedure Need (Name : String) is
      begin Expect (Status = OK, Name & Outcome'Image (Status)); end Need;
   begin
      for I in Packages'Range loop
         MC_FS.Open_Read (Media, "order/" & (if I = 1 then "a" else "b") & ".deb", File, Status); Need ("order fixture");
         MC_Store.Import_File (Store, File, Limit, Packages (I).Original, Status); Need ("order original retained"); MC_FS.Close (File);
         Pkg_Deb_Metadata.Inspect (Store, Packages (I).Original, Deadline, Observed.all, Status); Need ("order metadata");
         Packages (I).Control := Observed.Control;
         P.Stage (Store, Packages (I).Original, Deadline, Source, Status); Need ("order payload");
         X.Add (Payload, Source, Deadline, Status); Need ("order index");
         C.Add (Value, Store, Packages (I).Original, Deadline, Status); Need ("order candidate");
      end loop;
      Free (Observed); P.Clear (Source);
      X.Seal (Payload, Deadline, Status); Need ("order sealed index");
      C.Seal (Value, Packages, Payload, Deadline, Status); Need ("order sealed candidate");
      Pkg_Catalog_Store.Save (Store, Value, Deadline, Catalog, Status); Need ("order saved catalog");
      Pkg_Catalog_Retention.Prepare (Store, Catalog, Deadline, Closure, Status); Need ("order retained catalog");
      for Case_Number in 0 .. 7 loop
         declare
            Chosen : A.Selection (1 .. X.Path_Count (Payload));
            Cursor : Positive := 1; Item : X.Claim; State : X.Path_State;
            Directory_Claims, Positions : array (1 .. 3) of Positive := (others => 1);
            Wire : Bytes (1 .. A.Header_Size + 8 * Chosen'Length); Used, Root_Size : Natural;
            Root, Old : Bytes (1 .. 32_768) := (others => 0);
         begin
            for I in Chosen'Range loop
               X.Read_Claim (Payload, Cursor, Item, Status); Need ("order path");
               X.Inspect_Path (Payload, P.Byte_Strings.To_String (Item.Item.Path), State, Status); Need ("order claims");
               Chosen (I) := State.First;
               if Item.Item.Values.Kind = P.Directory then
                  declare Name : constant String := P.Byte_Strings.To_String (Item.Item.Path);
                     Depth : constant Positive := (if Name = "" then 1 elsif Name = "alpha" then 2 else 3);
                     Owner : constant Positive := 1 + (Case_Number / 2 ** (Depth - 1)) mod 2;
                  begin
                     Expect (Name in "" | "alpha" | "alpha/beta", "known directory fixture");
                     for J in State.First .. State.Last loop
                        X.Read_Claim (Payload, J, Item, Status); Need ("order directory owner");
                        if Item.Source.Original = Packages (Owner).Original then Chosen (I) := J; end if;
                     end loop;
                     Directory_Claims (Depth) := Chosen (I); Positions (Depth) := Depth;
                  end;
               end if;
               Cursor := State.Last + 1;
            end loop;
            A.Build (Store, Catalog, Closure, Chosen, Limit, Deadline, Manifest, Archive, Status); Need ("ordered multi-owner root");
            A.Verify_Ownership (Store, Manifest, Catalog, Closure, "amd64", Limit, Deadline, Again, Owned, Status);
            Need ("ordered root ownership and physical order");
            Expect (Again = Archive and then Owned /= Zero_Digest, "ordered exact identity");
            MC_Store.Read_Object (Store, Manifest, Wire, Used, Status); Need ("ordered manifest read");
            Expect (Used = Wire'Length and then Wire (8) = Character'Pos ('2'), "explicit v2 order format");
            MC_Store.Read_Object (Store, Archive, Root, Root_Size, Status); Need ("ordered root read");
            for Rank in 1 .. 3 loop
               declare Name : constant String := (case Rank is when 1 => "./", when 2 => "./alpha/", when 3 => "./alpha/beta/");
                  Start : constant Positive := (Rank - 1) * 512 + 1;
               begin
                  for J in Name'Range loop
                     Expect (Root (Start + J - 1) = Character'Pos (Name (J)), "root and parent before child header");
                  end loop;
                  Expect (Root (Start + Name'Length) = 0, "exact directory header name");
               end;
            end loop;
            Ada.Text_IO.Put_Line ("ORDER" & Integer'Image (Case_Number) & " " & MC_Hex.Encode (Manifest) & " " & MC_Hex.Encode (Archive));
            -- Independent tiny historical fixture: permute only the three
            -- unextended directory spans into old (source, ordinal) order.
            for I in 1 .. 3 loop
               for J in I + 1 .. 3 loop
                  declare Left, Right : X.Claim; Swap : Positive; begin
                     X.Read_Claim (Payload, Directory_Claims (Positions (I)), Left, Status); Need ("legacy left claim");
                     X.Read_Claim (Payload, Directory_Claims (Positions (J)), Right, Status); Need ("legacy right claim");
                     if Right.Source.Original < Left.Source.Original or else
                        (Right.Source.Original = Left.Source.Original and then Right.Source_Position < Left.Source_Position)
                     then Swap := Positions (I); Positions (I) := Positions (J); Positions (J) := Swap; end if;
                  end;
               end loop;
            end loop;
            Old := Root;
            for I in 1 .. 3 loop
               Old ((I - 1) * 512 + 1 .. I * 512) := Root ((Positions (I) - 1) * 512 + 1 .. Positions (I) * 512);
            end loop;
            Expect (Old (1 .. 1_536) /= Root (1 .. 1_536), "legacy order differs for this owner selection");
            MC_Store.Put (Store, Old (1 .. Root_Size), Legacy_Archive, Status); Need ("retain historical tar fixture");
            Wire (8) := Character'Pos ('1'); Wire (105 .. 136) := Legacy_Archive;
            MC_Store.Put (Store, Wire, Legacy, Status); Need ("retain historical manifest fixture");
            A.Verify (Store, Legacy, Limit, Deadline, Again, Status); Need ("historical v1 still verifies");
            Expect (Again = Legacy_Archive, "historical archive is not rewritten");
            A.Verify_Target (Store, Legacy, Catalog, Closure, Limit, Deadline, Again, Status); Need ("historical target binding");
            A.Verify_Ownership (Store, Legacy, Catalog, Closure, "amd64", Limit, Deadline, Again, Owned, Status);
            Expect (Status = Unsupported and then Again = Zero_Digest and then Owned = Zero_Digest,
               "unsuitable historical order cannot enter physical staging");
            Ada.Text_IO.Put_Line ("LEGACY" & Integer'Image (Case_Number) & " " & MC_Hex.Encode (Legacy) & " " & MC_Hex.Encode (Legacy_Archive));
         end;
      end loop;
   exception when others => MC_FS.Close (File); Free (Observed); raise;
   end Run;
end Root_Archive_Order_Test;
