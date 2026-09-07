-- SPDX-License-Identifier: MIT
with MC_FS; with MC_Log; with MC_Log_Format; with MC_Atomic; with MC_Hex;
with MC_Request_Replay; with MC_SHA256; with MC_Text; with MC_Site_Policy;
with MC_Contract_Profile; with MC_Protocol;
package body MC_Receiver_Ledger with SPARK_Mode => Off is
   procedure Provision (Policy_Directory, Parent_Directory, New_Name : String;
                        Status : out Outcome) is
      Policy_Root, Parent_Root, New_Root : MC_FS.Root;
      F : MC_FS.File; J : MC_Log.Journal; P : MC_Site_Policy.Policy;
      D : Digest; E : MC_Log_Format.Log_Entry;
      procedure Close_All is
      begin
         MC_Log.Close(J); MC_FS.Close(F); MC_FS.Close(New_Root);
         MC_FS.Close(Parent_Root); MC_FS.Close(Policy_Root);
      end Close_All;
   begin
      Status := Invalid_Input;
      if not MC_Text.Identifier(New_Name) then return; end if;
      MC_FS.Open_Root(Policy_Directory,Policy_Root,Status,Private_Only=>True);
      if Status = OK then MC_Site_Policy.Load(Policy_Root,P,D,Status); end if;
      if Status = OK and then P.Contract /= MC_Contract_Profile.Fingerprint then Status := Unsupported; end if;
      if Status = OK then MC_FS.Open_Root(Parent_Directory,Parent_Root,Status,Private_Only=>True); end if;
      if Status = OK then MC_FS.Make_Directory(Parent_Root,New_Name,Status); end if;
      if Status = OK then MC_FS.Open_Root(Parent_Directory & "/" & New_Name,New_Root,Status,Private_Only=>True); end if;
      if Status = OK then MC_FS.Create_New(New_Root,"requests.log",F,Status); end if;
      if Status = OK then MC_FS.Sync(F,Status); end if; MC_FS.Close(F);
      if Status = OK then MC_FS.Sync_Parent(New_Root,"requests.log",Status); end if;
      if Status = OK then MC_Log.Open(New_Root,"requests.log",P.Root_ID,J,Status,Create_If_Missing=>False); end if;
      if Status = OK then
         E.Kind := MC_Request_Replay.Genesis; E.Root_ID := P.Root_ID; E.Operation_ID := P.Root_ID;
         E.Object := D; E.Generation := P.Serial;
         MC_Log.Append(J,E,Status);
      end if;
      Close_All;
   exception when others => Close_All; Status := Indeterminate;
   end Provision;
   procedure Observe (Ledger_Directory : String; Root_ID, Request_ID : Identity;
                      Expected_Envelope : Digest; Value : out Receipt;
                      Status : out Outcome) is
      R : MC_FS.Root; J : MC_Log.Journal; Replay : MC_Request_Replay.State;
      E : MC_Log_Format.Log_Entry; B : Bytes(1..416); Used : Natural;
      Target_Header : Digest := Zero_Digest; Seen : Boolean := False;
      H : MC_Protocol.Header;
      procedure Close_All is
      begin MC_Log.Close(J); MC_FS.Close(R); end Close_All;
   begin
      Value := (others => <>); Status := Invalid_Input;
      if Root_ID = Zero_Identity or else Request_ID = Zero_Identity or else Expected_Envelope = Zero_Digest then return; end if;
      MC_FS.Open_Root(Ledger_Directory,R,Status,Private_Only=>True);
      if Status = OK then MC_Log.Open(R,"requests.log",Root_ID,J,Status,Create_If_Missing=>False); end if;
      if Status /= OK then Close_All; return; end if;
      if MC_Log.Length(J) = 0 then Status := Corrupt; Close_All; return; end if;
      for I in 1 .. MC_Log.Length(J) loop
         MC_Log.Read(J,I,E,Status);
         if Status = OK then MC_Request_Replay.Consume(Replay,E,Status); end if;
         if Status /= OK then Close_All; return; end if;
         if E.Kind /= MC_Request_Replay.Genesis and then E.Operation_ID = Request_ID then
            if not Seen then
               if E.Kind /= MC_Request_Replay.Begun then Status := Corrupt; Close_All; return; end if;
               MC_Atomic.Read(R,"request-" & MC_Hex.Encode(Request_ID) & ".bin",B,Used,Status);
               if Status /= OK or else Used /= B'Length or else MC_SHA256.Hash(B) /= Expected_Envelope then
                  Status := Corrupt; Close_All; return;
               end if;
               MC_Protocol.Decode(B(1..160),H,Status);
               if Status /= OK or else H.Request_ID /= Request_ID or else H.Resource_ID /= Root_ID then
                  Status := Corrupt; Close_All; return;
               end if;
               Target_Header := MC_SHA256.Hash(B(1..160)); Seen := True;
            end if;
            if E.Object /= Target_Header then Status := Corrupt; Close_All; return; end if;
            Value.Request_ID := Request_ID; Value.Envelope_Digest := Expected_Envelope;
            Value.Sequence := E.Sequence; Value.Result := E.Result;
            Value.Raw_Record := MC_Log_Format.Encode(E);
            Value.Record_Digest := MC_SHA256.Hash(Value.Raw_Record);
            case E.Kind is
               when MC_Request_Replay.Begun | MC_Request_Replay.Unknown_Outcome => Value.State := In_Progress;
               when MC_Request_Replay.Known_OK => Value.State := Terminal_OK;
               when MC_Request_Replay.Known_Failure => Value.State := Terminal_Failure;
               when others => Status := Corrupt; Close_All; return;
            end case;
         end if;
      end loop;
      Close_All; Status := OK;
   exception when others => Close_All; Value := (others => <>); Status := IO_Error;
   end Observe;
end MC_Receiver_Ledger;
