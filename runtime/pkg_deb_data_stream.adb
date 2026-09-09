-- SPDX-License-Identifier: MIT
with Interfaces.C; with System;
with MC_Clock; with MC_FS; with MC_Posix; with MC_SHA256;
package body Pkg_Deb_Data_Stream with SPARK_Mode => Off is
   use Interfaces.C; use type System.Address; use type MC_FS.Entry_Info;
   use type Pkg_Deb_Container.Member_Kind;
   function New_Stream (Codec : int; Size, Limit : Interfaces.Unsigned_64; Result : access System.Address) return int
      with Import, Convention => C, External_Name => "nia_deb_stream_new";
   procedure Free_Stream (Handle : System.Address)
      with Import, Convention => C, External_Name => "nia_deb_stream_free";
   function Step (Handle, Input : System.Address; Input_Size : size_t; Consumed : access size_t;
                  Output : System.Address; Capacity : size_t; Produced : access size_t) return int
      with Import, Convention => C, External_Name => "nia_deb_stream_step";
   function Translate (RC : int) return Outcome is
     (case RC is when 0 | 1 => OK, when 2 => Corrupt, when 3 => Exhausted, when 4 => Unsupported, when others => IO_Error);
   procedure Stage (Store : in out MC_Store.Store; Expected : Pkg_Deb_Container.Envelope;
                    Limit, Deadline : Counter; Result : out Observation; Status : out Outcome) is
      Candidate : Observation;
      F : MC_FS.File; Before, After : MC_FS.Entry_Info; Writer : MC_Store.Writer;
      Handle : aliased System.Address := System.Null_Address;
      Codec : int; Now : Counter;
      procedure Cleanup is
      begin
         Free_Stream (Handle); Handle := System.Null_Address; MC_FS.Close (F); MC_Store.Abort_Write (Writer);
      end Cleanup;
      procedure Check_Time is
      begin
         MC_Clock.Boottime_Milliseconds (Now, Status);
         if Status = OK and then Now >= Deadline then Status := Stale; end if;
      end Check_Time;
      procedure Decode_Pass (Write_Output : Boolean; Hash : out Digest; Size : out Counter) is
         Input, Output : Bytes (1 .. 65_536);
         Available, Offset : Natural := 0;
         Read_Count : Natural; Fetched, Written : Counter := 0;
         Consumed, Produced : aliased size_t := 0;
         Input_Hash, Output_Hash : MC_SHA256.Context := MC_SHA256.Initialize;
         RC : int;
      begin
         Hash := Zero_Digest; Size := 0;
         Check_Time; if Status /= OK then return; end if;
         RC := New_Stream (Codec, Interfaces.Unsigned_64 (Candidate.Encoded_Size), Interfaces.Unsigned_64 (Limit), Handle'Access);
         Status := Translate (RC); if Status /= OK then return; end if;
         loop
            Check_Time; if Status /= OK then return; end if;
            if Offset = Available then
               Offset := 0; Available := 0;
               if Fetched < Candidate.Encoded_Size then
                  Available := Natural (Counter'Min (Counter (Input'Length), Candidate.Encoded_Size - Fetched));
                  MC_FS.Read_At (F, Fetched, Input (1 .. Available), Read_Count, Status);
                  if Status /= OK then return; end if;
                  if Read_Count /= Available then Status := Corrupt; return; end if;
                  MC_SHA256.Update (Input_Hash, Input (1 .. Available)); Fetched := Fetched + Counter (Available);
               end if;
            end if;
            RC := Step (Handle, Input (Offset + 1)'Address, size_t (Available - Offset), Consumed'Access,
                        Output'Address, Output'Length, Produced'Access);
            Status := Translate (RC); if Status /= OK then return; end if;
            if Consumed > size_t (Available - Offset) or else Produced > Output'Length then Status := Corrupt; return; end if;
            Check_Time; if Status /= OK then return; end if;
            Offset := Offset + Natural (Consumed);
            if Counter (Produced) > Limit - Written then Status := Exhausted; return; end if;
            Written := Written + Counter (Produced);
            MC_SHA256.Update (Output_Hash, Output (1 .. Natural (Produced)));
            if Write_Output then
               MC_Store.Write_Chunk (Writer, Output (1 .. Natural (Produced)), Status); if Status /= OK then return; end if;
            end if;
            exit when RC = 1;
            if Consumed = 0 and then Produced = 0 then Status := Corrupt; return; end if;
         end loop;
         if Fetched /= Candidate.Encoded_Size or else Offset /= Available
            or else MC_SHA256.Finish (Input_Hash) /= Candidate.Compressed then Status := Corrupt; return; end if;
         MC_FS.Info (F, After, Status); if Status /= OK then return; end if;
         if After /= Before then Status := Stale; return; end if;
         Hash := MC_SHA256.Finish (Output_Hash); Size := Written;
         Free_Stream (Handle); Handle := System.Null_Address;
      end Decode_Pass;
      Observed : Digest; Observed_Size : Counter;
   begin
      Result := (others => <>); Status := Denied;
      if MC_Posix.Euid = 0 then return; end if;
      if Limit > MC_Store.Max_Object_Size then Status := Exhausted; return; end if;
      if Expected.Data_Index = 0 or else Expected.Data_Index > Expected.Count
         or else Expected.Items (Expected.Data_Index).Kind /= Pkg_Deb_Container.Data_Archive then
         Status := Invalid_Input; return;
      end if;
      Check_Time; if Status /= OK then return; end if;
      Pkg_Deb_Container.Stage_Member (Store, Expected, Expected.Data_Index, Deadline, Candidate.Compressed, Status);
      if Status /= OK then return; end if;
      Candidate.Original := Expected.Original; Candidate.Encoded_Size := Expected.Items (Expected.Data_Index).Length;
      case Expected.Items (Expected.Data_Index).Codec is
         when Pkg_Deb_Container.Uncompressed => Codec := 0;
         when Pkg_Deb_Container.Gzip => Codec := 1;
         when Pkg_Deb_Container.Bzip2 => Codec := 2;
         when Pkg_Deb_Container.LZMA => Codec := 5;
         when Pkg_Deb_Container.XZ => Codec := 6;
         when Pkg_Deb_Container.Zstd => Codec := 14;
      end case;
      MC_Store.Open_Object (Store, Candidate.Compressed, F, Status); if Status /= OK then Cleanup; return; end if;
      MC_FS.Info (F, Before, Status); if Status /= OK then Cleanup; return; end if;
      if Before.Size /= Candidate.Encoded_Size then Status := Corrupt; Cleanup; return; end if;
      Decode_Pass (False, Candidate.Expanded, Candidate.Expanded_Size); if Status /= OK then Cleanup; return; end if;
      Check_Time; if Status /= OK then Cleanup; return; end if;
      MC_Store.Begin_Write (Store, Candidate.Expanded, Candidate.Expanded_Size, Writer, Status);
      if Status /= OK then Cleanup; return; end if;
      Decode_Pass (True, Observed, Observed_Size); if Status /= OK then Cleanup; return; end if;
      if Observed /= Candidate.Expanded or else Observed_Size /= Candidate.Expanded_Size then Status := Corrupt; Cleanup; return; end if;
      Check_Time; if Status /= OK then Cleanup; return; end if;
      MC_Store.Finish_Write (Store, Writer, Status); if Status /= OK then Cleanup; return; end if;
      Check_Time; if Status = OK then Result := Candidate; end if;
      Cleanup;
   exception
      when Storage_Error => Cleanup; Result := (others => <>); Status := Exhausted;
      when others => Cleanup; Result := (others => <>); Status := IO_Error;
   end Stage;
end Pkg_Deb_Data_Stream;
