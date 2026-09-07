-- SPDX-License-Identifier: MIT
package body Pkg_Journal_IO with SPARK_Mode => Off is
   use Pkg_Journal;
   procedure Scan
     (File : MC_Durable.File_Handle; Expected_Root : Identity;
      Result : out Head; Status : out Outcome) is
      Length, Offset : Counter := 0;
      Raw : Encoded_Record;
      Item : Log_Record;
   begin
      Result := (Root_ID => Expected_Root, others => <>);
      Status := Invalid_Input;
      if Is_Zero(Expected_Root) then return; end if;
      MC_Durable.Size(File,Length,Status);
      if Status /= OK then return; end if;
      if Length mod Record_Size /= 0 then Status := Corrupt; return; end if;
      if Length / Record_Size > 1_000_000 then Status := Exhausted; return; end if;
      while Offset < Length loop
         MC_Durable.Read_At(File,Offset,Raw,Status);
         if Status /= OK then return; end if;
         Decode(Raw,Item,Status);
         if Status /= OK then return; end if;
         Extend(Result,Item,Status);
         if Status /= OK then return; end if;
         Offset := Offset+Record_Size;
      end loop;
      Status := OK;
   end Scan;
   procedure Check_Anchor
     (Actual, Authenticated_Anchor : Head; Status : out Outcome) is
   begin
      if Actual = Authenticated_Anchor and then not Is_Zero(Actual.Root_ID) then
         Status := OK;
      else Status := Corrupt; end if;
   end Check_Anchor;
   procedure Append
     (File : in out MC_Durable.File_Handle; State : in out Head;
      Item : Log_Record; Status : out Outcome) is
      Candidate : Head := State;
      Raw : Encoded_Record;
   begin
      Extend(Candidate,Item,Status);
      if Status /= OK then return; end if;
      if State.Sequence_Number > Counter'Last/Record_Size then Status := Exhausted; return; end if;
      Raw := Encode(Item);
      MC_Durable.Append(File,State.Sequence_Number*Record_Size,Raw,Status);
      if Status = OK then State := Candidate; end if;
   end Append;
end Pkg_Journal_IO;
