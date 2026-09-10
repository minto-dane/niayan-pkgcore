-- SPDX-License-Identifier: BSD-3-Clause
with Ada.Command_Line; with Ada.Text_IO;
with MC_Types; use MC_Types;
with MC_Runtime; with MC_Clock; with MC_FS; with MC_Store; with MC_Hex;
with Pkg_Deb_Conffiles; with Pkg_Deb_Payload; with Pkg_Conffile_Transition;
with Test_Support; use Test_Support;
procedure Run_Conffile_Tests with SPARK_Mode => Off is
   package C renames Pkg_Deb_Conffiles; package T renames Pkg_Conffile_Transition;
   use type T.Action; use type T.Backup_Kind; use type Pkg_Deb_Payload.Entry_Kind;
   Store : MC_Store.Store; Root : MC_FS.Root; File : MC_FS.File; Inventory : C.Inventory;
   Item : C.Declaration; Hash : Digest; Status : Outcome; Deadline : Counter;
   Result : T.Decision;
   procedure Need (Label_Text : String) is
   begin Expect (Status = OK, Label_Text & Outcome'Image (Status)); end Need;
   function Image (Text : String) return T.Image is
      Value : T.Image;
   begin
      if Text = "-" then return Value; end if;
      Value.Kind := T.Regular; MC_Hex.Decode (Text, Value.Content, Status); Need ("image hash"); return Value;
   end Image;
   procedure Inspect (Name : String; Accepted : Boolean) is
   begin
      MC_FS.Open_Read (Root, Name & ".deb", File, Status); Need ("open fixture");
      MC_Store.Import_File (Store, File, MC_Store.Max_Object_Size, Hash, Status); Need ("retain original"); MC_FS.Close (File);
      C.Inspect (Store, Hash, Deadline, Inventory, Status);
      if Accepted then
         Need ("native conffiles " & Name);
         Expect (C.Original_Hash (Inventory) = Hash, "exact original");
      else
         Expect (Status /= OK, "rejected declaration " & Name);
         Expect (C.Count (Inventory) = 0, "cleared declaration count");
         Expect (C.Original_Hash (Inventory) = Zero_Digest, "cleared declaration binding");
      end if;
   end Inspect;
begin
   MC_Runtime.Initialize (Status); Need ("runtime");
   if Ada.Command_Line.Argument_Count = 7 then
      Expect (Ada.Command_Line.Argument (7) = "decision", "explicit comparison mode");
      T.Decide (T.Operation'Value (Ada.Command_Line.Argument (1)), Boolean'Value (Ada.Command_Line.Argument (2)),
         Image (Ada.Command_Line.Argument (3)), Image (Ada.Command_Line.Argument (4)), Image (Ada.Command_Line.Argument (5)),
         T.Choice'Value (Ada.Command_Line.Argument (6)), Result, Status); Need ("decision");
      Ada.Text_IO.Put_Line ("EFFECT " & T.Action'Image (Result.Effect));
      Ada.Text_IO.Put_Line ("CONTENT " & MC_Hex.Encode (Result.Content));
      Ada.Text_IO.Put_Line ("BACKUP " & T.Backup_Kind'Image (Result.Backup));
      Ada.Text_IO.Put_Line ("BACKUP_CONTENT " & MC_Hex.Encode (Result.Backup_Content));
      Ada.Text_IO.Put_Line ("NEXT_VENDOR " & MC_Hex.Encode (Result.Next_Vendor.Content));
      Report; return;
   end if;
   Expect (Ada.Command_Line.Argument_Count = 2, "private store and fixtures");
   MC_Clock.Boottime_Milliseconds (Deadline, Status); Need ("clock"); Deadline := Deadline + 120_000;
   MC_Store.Initialize (Ada.Command_Line.Argument (1), Store, Status); Need ("private CAS");
   MC_FS.Open_Root (Ada.Command_Line.Argument (2), Root, Status); Need ("fixture root");
   Inspect ("normal", True); Expect (C.Count (Inventory) = 1, "one declaration");
   C.Read_Entry (Inventory, 1, Item, Status); Need ("read declaration");
   Expect (Pkg_Deb_Payload.Byte_Strings.To_String (Item.Path) = "/etc/fixture.conf" and then Item.Present
      and then not Item.Remove_On_Upgrade and then Item.Payload.Values.Content /= Zero_Digest, "real retained payload content");
   Inspect ("absent", True); Expect (C.Count (Inventory) = 0 and then C.Declaration_Hash (Inventory) = Zero_Digest, "absent distinct");
   Inspect ("empty", True); Expect (C.Count (Inventory) = 0 and then C.Declaration_Hash (Inventory) /= Zero_Digest, "empty file retained");
   Inspect ("missing", True); C.Read_Entry (Inventory, 1, Item, Status); Need ("missing entry"); Expect (not Item.Present, "no invented empty payload");
   Inspect ("remove", True); C.Read_Entry (Inventory, 1, Item, Status); Need ("removal entry"); Expect (Item.Remove_On_Upgrade and then not Item.Present, "removal flag");
   Inspect ("no-final-newline", True); Inspect ("space-name", True); Inspect ("byte-name", True);
   Inspect ("symbolic", True); C.Read_Entry (Inventory, 1, Item, Status); Need ("link entry");
   Expect (Item.Payload.Values.Kind = Pkg_Deb_Payload.Symbolic_Link, "link kind not flattened");
   Inspect ("blank", False); Inspect ("whitespace", False); Inspect ("duplicate", False); Inspect ("remove-present", False);
   Inspect ("unknown-flag", False); Inspect ("relative", False); Inspect ("traversal", False); Inspect ("nul", False); Inspect ("empty-component", False);
   T.Decide (T.Install_Upgrade, True, (T.Regular, (others => 1)), (T.Other, Zero_Digest), (T.Regular, (others => 2)), T.Unresolved, Result, Status);
   Expect (Status = Unsupported and then Result.Content = Zero_Digest, "unreadable is not missing");
   T.Decide (T.Install_Upgrade, True, (T.Regular, (others => 1)), (T.Missing, (others => 1)), (T.Regular, (others => 2)), T.Unresolved, Result, Status);
   Expect (Status = Invalid_Input and then Result.Content = Zero_Digest, "invalid missing representation");
   C.Clear (Inventory); MC_FS.Close (Root); MC_Store.Close (Store); Report;
exception when others => C.Clear (Inventory); MC_FS.Close (File); MC_FS.Close (Root); MC_Store.Close (Store); raise;
end Run_Conffile_Tests;
