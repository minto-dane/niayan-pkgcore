-- SPDX-License-Identifier: BSD-3-Clause
-- Internal read-only deployment check, not a generation execution command.
with Ada.Command_Line; with Ada.Text_IO;
with MC_Types; use MC_Types;
with MC_Runtime; with MC_Hex; with MC_Clock;
with Pkg_Site_Supply; with Pkg_Supply_Policy;
procedure Pkg_Supply_Observe with SPARK_Mode => Off is
   use Ada.Command_Line; use Ada.Text_IO;
   Context : Pkg_Site_Supply.Session; Value : Pkg_Supply_Policy.Snapshot;
   Root_ID, Transaction_ID : Identity;
   Plan, Policy, Map : Digest := Zero_Digest;
   Deadline : Counter; Status : Outcome := Invalid_Input;
   Planning : constant Boolean := Argument_Count = 5 and then Argument (1) = "--planning";
   Offset : constant Natural := (if Planning then 1 else 0);
begin
   if not Planning and then Argument_Count /= 7 then Set_Exit_Status (64); return; end if;
   MC_Runtime.Initialize (Status);
   if Status = OK then MC_Hex.Decode (Argument (3 + Offset), Root_ID, Status); end if;
   if Status = OK then MC_Hex.Decode (Argument (4 + Offset), Transaction_ID, Status); end if;
   if not Planning then
      if Status = OK then MC_Hex.Decode (Argument (5), Plan, Status); end if;
      if Status = OK then MC_Hex.Decode (Argument (6), Policy, Status); end if;
      if Status = OK then MC_Hex.Decode (Argument (7), Map, Status); end if;
   end if;
   if Status = OK then MC_Clock.Boottime_Milliseconds (Deadline, Status); end if;
   if Status = OK then
      if Deadline >= Counter'Last - 5_000 then Status := Exhausted;
      else Deadline := Deadline + 5_000; end if;
   end if;
   if Status = OK then
      if Planning then
         Pkg_Site_Supply.Open_Planning (Argument (2), Argument (3), Root_ID, Transaction_ID,
            Deadline, Context, Status);
      else
         Pkg_Site_Supply.Open (Argument (1), Argument (2), Root_ID, Transaction_ID,
            Plan, Policy, Map, Deadline, Context, Status);
      end if;
   end if;
   if Status = OK then
      if Planning then
         Pkg_Site_Supply.Observe_Planning (Context, Root_ID, Transaction_ID, Value, Status);
      else
         Pkg_Site_Supply.Observe (Context, Root_ID, Transaction_ID, Plan, Policy, Value, Status);
      end if;
   end if;
   Pkg_Site_Supply.Close (Context);
   Put_Line ("format=nia-site-supply-1"); Put_Line ("status=" & Outcome'Image (Status));
   if Status = OK then
      if Planning then Put_Line ("planning=true"); end if;
      Put_Line ("map=" & MC_Hex.Encode (Value.Map));
      Put_Line ("observed_at=" & Counter'Image (Value.Observed_At));
      Put_Line ("authorities=" & Natural'Image (Value.Count));
      for I in 1 .. Value.Count loop
         Put_Line ("authority=" & MC_Hex.Encode (Value.Trusted (I).Scope) & " " & MC_Hex.Encode (Value.Trusted (I).Key)
            & Counter'Image (Value.Trusted (I).Minimum_Epoch) & Counter'Image (Value.Trusted (I).Maximum_Age));
      end loop;
      Put_Line ("execution_permit=false");
   else Set_Exit_Status (2); end if;
exception when others =>
   Pkg_Site_Supply.Close (Context); Put_Line ("status=INDETERMINATE"); Set_Exit_Status (2);
end Pkg_Supply_Observe;
