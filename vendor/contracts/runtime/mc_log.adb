-- SPDX-License-Identifier: MIT
with MC_Journal_Budget; with MC_SHA256; with MC_Posix; with Interfaces.C;
package body MC_Log with SPARK_Mode => Off is
   use type Interfaces.C.int;
   procedure Open(R : MC_FS.Root; Path : String; Root_ID : Identity;
                  J : in out Journal; Status : out Outcome;
                  Create_If_Missing : Boolean := True) is
      V : MC_FS.Entry_Info; B : MC_Log_Format.Frame; E : MC_Log_Format.Log_Entry; Used : Natural;
      Previous : Digest:=Zero_Digest;
   begin
      Status:=Invalid_Input;
      if J.Opened or else Root_ID=Zero_Identity then return; end if;
      MC_FS.Open_Locked(R,Path,J.F,Status,Create_If_Missing); if Status/=OK then return; end if;
      MC_FS.Info(J.F,V,Status); if Status/=OK then Close(J); return; end if;
      if V.Size/256>Max_Records then Status:=Exhausted; Close(J); return; end if;
      J.Count:=V.Size/256; J.Tail_Bytes:=Natural(V.Size mod 256); J.Root_ID:=Root_ID;
      for I in 1..J.Count loop
         MC_FS.Read_At(J.F,(I-1)*256,B,Used,Status);
         if Status/=OK or else Used/=256 then Status:=Corrupt; Close(J); return; end if;
         MC_Log_Format.Decode(B,E,Status);
         if Status/=OK or else E.Sequence/=I or else E.Root_ID/=Root_ID or else E.Previous/=Previous
         then Status:=Corrupt; Close(J); return; end if;
         Previous:=MC_SHA256.Hash(B);
      end loop;
      J.Last_Digest:=Previous; J.Opened:=True; J.Poisoned:=False;
      Status:=(if J.Tail_Bytes=0 then OK else Indeterminate);
   end Open;
   procedure Read(J : Journal; Index : Counter; E : out MC_Log_Format.Log_Entry; Status : out Outcome) is
      B : MC_Log_Format.Frame; Used : Natural;
   begin
      E:=(others=><>); Status:=Invalid_Input;
      if not J.Opened or else Index=0 or else Index>J.Count then return; end if;
      MC_FS.Read_At(J.F,(Index-1)*256,B,Used,Status); if Status/=OK then return; end if;
      if Used/=256 then Status:=Corrupt; return; end if;
      MC_Log_Format.Decode(B,E,Status);
      if Status=OK and then (E.Sequence/=Index or else E.Root_ID/=J.Root_ID) then Status:=Corrupt; end if;
   end Read;
   procedure Append(J : in out Journal; E : in out MC_Log_Format.Log_Entry; Status : out Outcome) is
      B : MC_Log_Format.Frame;
   begin
      Status:=Invalid_Input;
      if not J.Opened or else J.Poisoned or else J.Tail_Bytes/=0 then return; end if;
      if J.Count=Max_Records then Status:=Exhausted; return; end if;
      if E.Kind=0 or else E.Operation_ID=Zero_Identity or else E.Root_ID/=J.Root_ID then return; end if;
      E.Sequence:=J.Count+1; E.Previous:=J.Last_Digest; B:=MC_Log_Format.Encode(E);
      MC_FS.Append_Durable(J.F,J.Count*256,B,Status);
      if Status=OK then J.Count:=J.Count+1; J.Last_Digest:=MC_SHA256.Hash(B);
      else J.Poisoned:=True; Status:=Indeterminate; end if;
   end Append;
   function Length(J : Journal) return Counter is (J.Count);
   function Head(J : Journal) return Digest is (J.Last_Digest);
   function Can_Append (J : Journal; Records : Counter;
                        After_Tail_Repair : Boolean := False) return Boolean is
     (J.Opened and then not J.Poisoned
      and then (J.Tail_Bytes=0 or else After_Tail_Repair)
      and then MC_Journal_Budget.Fits(J.Count,Max_Records,0,Records));
   function Has_Torn_Tail(J : Journal) return Boolean is (J.Tail_Bytes/=0);
   procedure Export_Tail(J : Journal; Data : out Bytes; Used : out Natural; Status : out Outcome) is
   begin
      Data:=(others=>0); Used:=0; Status:=Invalid_Input;
      if not J.Opened or else Data'Length<J.Tail_Bytes then return; end if;
      MC_FS.Read_At(J.F,J.Count*256,Data,Used,Status);
      if Status=OK and then Used/=J.Tail_Bytes then Status:=Conflict; end if;
   end Export_Tail;
   procedure Repair_Tail(J : in out Journal; Preserved_Tail : Digest; Status : out Outcome) is
      B : Bytes(1..256); Used : Natural;
   begin
      Status:=Invalid_Input;
      if not J.Opened or else J.Poisoned or else J.Tail_Bytes=0 then return; end if;
      Export_Tail(J,B,Used,Status); if Status/=OK then return; end if;
      if MC_SHA256.Hash(B(1..Used))/=Preserved_Tail then Status:=Denied; return; end if;
      if MC_Posix.Ftruncate(Interfaces.C.int(MC_FS.Native(J.F)),Interfaces.C.long(J.Count*256))/=0
      then Status:=IO_Error; return; end if;
      MC_FS.Sync(J.F,Status);
      if Status=OK then J.Tail_Bytes:=0; else J.Poisoned:=True; Status:=Indeterminate; end if;
   end Repair_Tail;
   procedure Close(J : in out Journal) is
   begin MC_FS.Close(J.F); J.Opened:=False; J.Poisoned:=False; J.Count:=0; J.Tail_Bytes:=0;
      J.Root_ID:=Zero_Identity; J.Last_Digest:=Zero_Digest; end;
end MC_Log;
