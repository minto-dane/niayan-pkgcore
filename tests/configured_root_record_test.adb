-- SPDX-License-Identifier: BSD-3-Clause
with Ada.Command_Line; with Ada.Text_IO;
with MC_Types; use MC_Types;
with MC_Clock; with MC_Hex; with MC_Runtime; with MC_Store;
with Pkg_Configured_Root_Record;
with Test_Support; use Test_Support;
package body Configured_Root_Record_Test is
   procedure Run is
      package R renames Pkg_Configured_Root_Record;
      Store : MC_Store.Store; Value : R.View; Bound : R.Root_Binding;
      Status : Outcome; Deadline : Counter; Manifest, Retained, Member : Digest;
      Choice : R.Saved_Choice; Configured : R.Saved_Configuration;
      procedure Load (Until_Time : Counter) is
      begin R.Load (Store, Manifest, Retained, MC_Store.Max_Object_Size, Until_Time, Value, Status); end Load;
      procedure Empty_View is
      begin
         Expect (R.Binding (Value).Archive = Zero_Digest and then R.Object_Count (Value) = 0
            and then R.Choice_Count (Value) = 0 and then R.Configuration_Count (Value) = 0, "failed saved read clears view");
      end Empty_View;
   begin
      MC_Runtime.Initialize (Status); Expect (Status = OK, "saved runtime");
      MC_Clock.Boottime_Milliseconds (Deadline, Status); Expect (Status = OK, "saved clock"); Deadline := Deadline + 600_000;
      MC_Hex.Decode (Ada.Command_Line.Argument (3), Manifest, Status); Expect (Status = OK, "saved manifest digest");
      MC_Hex.Decode (Ada.Command_Line.Argument (4), Retained, Status); Expect (Status = OK, "saved retention digest");
      MC_Store.Open (Ada.Command_Line.Argument (1), Store, Status); Expect (Status = OK, "reopen saved CAS without bootstrap");
      Load (Deadline);
      if Ada.Command_Line.Argument (5) = "reject" then
         Expect (Status /= OK, "saved malformed or missing references refused"); Empty_View;
         Ada.Text_IO.Put_Line ("REFUSED " & Outcome'Image (Status));
      else
         Expect (Ada.Command_Line.Argument (5) = "accept" and then Status = OK, "saved read " & Outcome'Image (Status));
         Bound := R.Binding (Value);
         Ada.Text_IO.Put_Line ("BINDING " & MC_Hex.Encode (Bound.Base.Manifest) & " " & MC_Hex.Encode (Bound.Base.Catalog)
            & " " & MC_Hex.Encode (Bound.Base.Closure) & " " & MC_Hex.Encode (Bound.Base.Archive)
            & " " & MC_Hex.Encode (Bound.Base.Ownership) & " " & MC_Hex.Encode (Bound.Base.Root_ID)
            & " " & MC_Hex.Encode (Bound.Base.Transaction) & " " & MC_Hex.Encode (Bound.Base.Context)
            & " " & MC_Hex.Encode (Bound.Architecture) & " " & MC_Hex.Encode (Bound.Archive)
            & Counter'Image (Bound.Size) & Counter'Image (Bound.Entries));
         for I in 1 .. R.Choice_Count (Value) loop
            R.Read_Choice (Value, I, Choice, Status); Expect (Status = OK, "saved ordered choice");
            Ada.Text_IO.Put_Line ("CHOICE " & MC_Hex.Encode (Choice.Proposal) & " " & MC_Hex.Encode (Choice.Decision)
               & " " & MC_Hex.Encode (Choice.Closure));
         end loop;
         for I in 1 .. R.Configuration_Count (Value) loop
            R.Read_Configuration (Value, I, Configured, Status); Expect (Status = OK, "saved configured entry");
            Ada.Text_IO.Put_Line ("ENTRY" & Natural'Image (Configured.Position) & " " & MC_Hex.Encode (Configured.Prefix)
               & " " & MC_Hex.Encode (Configured.Content) & Counter'Image (Configured.Size));
         end loop;
         for I in 1 .. R.Object_Count (Value) loop
            R.Read_Object (Value, I, Member, Status); Expect (Status = OK, "saved sorted member");
            Ada.Text_IO.Put_Line ("MEMBER " & MC_Hex.Encode (Member));
         end loop;
         R.Read_Choice (Value, R.Choice_Count (Value) + 1, Choice, Status);
         Expect (Status = Invalid_Input and then Choice.Proposal = Zero_Digest, "saved choice index clears output");
         R.Read_Configuration (Value, R.Configuration_Count (Value) + 1, Configured, Status);
         Expect (Status = Invalid_Input and then Configured.Position = 0, "saved entry index clears output");
         R.Read_Object (Value, R.Object_Count (Value) + 1, Member, Status);
         Expect (Status = Invalid_Input and then Member = Zero_Digest, "saved member index clears output");
         Load (0); Expect (Status = Stale, "saved deadline refusal"); Empty_View;
         Load (Counter'Last); Expect (Status = Stale, "saved infinite deadline refused"); Empty_View;
      end if;
      R.Clear (Value); MC_Store.Close (Store); Report;
   exception when others => R.Clear (Value); MC_Store.Close (Store); raise;
   end Run;
end Configured_Root_Record_Test;
