-- SPDX-License-Identifier: BSD-3-Clause
-- Internal installer boundary; never an automatic startup repair operation.
with Ada.Command_Line; with Ada.Text_IO; with Interfaces.C;
with MC_Posix; with MC_Runtime; with MC_Store;
with MC_Types; use MC_Types;
procedure Pkg_Store_Bootstrap with SPARK_Mode => Off is
   use Ada.Command_Line; use type Interfaces.C.unsigned;
   Store : MC_Store.Store;
   Status : Outcome := Invalid_Input;
begin
   if Argument_Count /= 2 or else Argument (1) not in "initialize" | "check" then
      Ada.Text_IO.Put_Line ("format=nia-store-bootstrap-1");
      Ada.Text_IO.Put_Line ("status=INVALID_INPUT");
      Set_Exit_Status (64); return;
   end if;
   MC_Runtime.Initialize (Status);
   if Status = OK then
      if MC_Posix.Euid = 0 then
         Status := Denied;
      elsif Argument (1) = "initialize" then
         MC_Store.Initialize (Argument (2), Store, Status);
      else
         MC_Store.Open (Argument (2), Store, Status);
      end if;
   end if;
   MC_Store.Close (Store);
   Ada.Text_IO.Put_Line ("format=nia-store-bootstrap-1");
   Ada.Text_IO.Put_Line ("status=" & Outcome'Image (Status));
   -- A structural check does not verify retained objects or admit a generation.
   if Status /= OK then Set_Exit_Status (2); end if;
exception when others =>
   MC_Store.Close (Store);
   Ada.Text_IO.Put_Line ("format=nia-store-bootstrap-1");
   Ada.Text_IO.Put_Line ("status=INDETERMINATE");
   Set_Exit_Status (2);
end Pkg_Store_Bootstrap;
