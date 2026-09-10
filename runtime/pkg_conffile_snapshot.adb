-- SPDX-License-Identifier: BSD-3-Clause
with Interfaces.C; with MC_Clock; with MC_Posix;
package body Pkg_Conffile_Snapshot with SPARK_Mode => Off is
   use type System.Address; use type Interfaces.C.int; use type Interfaces.C.long;
   use type Interfaces.C.unsigned; use type Interfaces.C.unsigned_long_long;
   function Take (Root : Interfaces.C.int; Path : System.Address;
      Limit, Deadline : Interfaces.C.unsigned_long_long; Handle : System.Address) return Interfaces.C.int
     with Import, Convention => C, External_Name => "nia_conffile_capture";
   function Check (Handle : System.Address; Deadline : Interfaces.C.unsigned_long_long) return Interfaces.C.int
     with Import, Convention => C, External_Name => "nia_conffile_recheck";
   function Data (Handle, FD, Size, Meta, Used, Content : System.Address) return Interfaces.C.int
     with Import, Convention => C, External_Name => "nia_conffile_data";
   procedure Close (Handle : System.Address)
     with Import, Convention => C, External_Name => "nia_conffile_close";
   function Result (Code : Interfaces.C.int) return Outcome is
     (case Code is when 0 => OK, when 1 => Invalid_Input, when 2 => Unsupported,
      when 3 => Denied, when 5 => Stale, when 6 => Exhausted, when 7 => IO_Error,
      when others => Indeterminate);
   procedure Clear (Value : in out Snapshot) is
   begin
      Close (Value.Handle); Value.Handle := System.Null_Address; Value.Reservation := -1;
      Value.Image := (Pkg_Conffile_Transition.Other, Zero_Digest); Value.Meta := Zero_Digest;
   end Clear;
   overriding procedure Finalize (Value : in out Snapshot) is
   begin Clear (Value); end Finalize;
   function Current (Value : Snapshot) return Pkg_Conffile_Transition.Image is (Value.Image);
   function Metadata (Value : Snapshot) return Digest is (Value.Meta);
   procedure Recheck (Store : MC_Store.Store; Value : in out Snapshot;
      Deadline : Counter; Status : out Outcome) is
   begin
      Status := Invalid_Input;
      if Value.Handle /= System.Null_Address and then Value.Reservation >= 0
        and then MC_Store.Native_Reservation (Store) = Value.Reservation then
         Status := Result (Check (Value.Handle, Interfaces.C.unsigned_long_long (Deadline)));
      end if;
      if Status /= OK then Clear (Value); end if;
   exception when others => Clear (Value); Status := Indeterminate;
   end Recheck;
   procedure Capture (Store : in out MC_Store.Store; Root_FD : Integer;
      Path : String; Limit, Deadline : Counter; Value : in out Snapshot; Status : out Outcome) is
      Name : aliased constant String := Path & Character'Val (0);
      Handle, Meta : aliased System.Address := System.Null_Address;
      FD : aliased Interfaces.C.int := -1;
      Size : aliased Interfaces.C.unsigned_long_long := 0;
      Used : aliased Interfaces.C.unsigned := 0;
      Content, Meta_Hash : Digest := Zero_Digest;
      Buffer : Bytes (1 .. 65_536); Writer : MC_Store.Writer;
      Offset : Counter := 0; Now : Counter; Read : Interfaces.C.long;
      Interrupted : exception;
      procedure Need is
      begin if Status /= OK then raise Interrupted; end if; end Need;
      procedure Clock is
      begin
         MC_Clock.Boottime_Milliseconds (Now, Status); Need;
         if Now >= Deadline then Status := Stale; raise Interrupted; end if;
      end Clock;
      procedure Cleanup is
      begin MC_Store.Abort_Write (Writer); Close (Handle); Handle := System.Null_Address; end Cleanup;
   begin
      Clear (Value); Status := Denied;
      if MC_Posix.Euid = 0 then return; end if;
      Status := Invalid_Input;
      if Root_FD < 0 or else MC_Store.Native_Reservation (Store) < 0
        or else Limit > MC_Store.Max_Object_Size or else Path'Length not in 2 .. 4_096
        or else (for some C of Path => C = Character'Val (0)) then return; end if;
      Clock;
      Status := Result (Take (Interfaces.C.int (Root_FD), Name'Address,
         Interfaces.C.unsigned_long_long (Limit), Interfaces.C.unsigned_long_long (Deadline), Handle'Address)); Need;
      Status := Result (Data (Handle, FD'Address, Size'Address, Meta'Address, Used'Address, Content'Address)); Need;
      if Size > Interfaces.C.unsigned_long_long (Limit) or else Used not in 1 .. 196_608
        or else Meta = System.Null_Address then Status := Corrupt; raise Interrupted; end if;
      if FD >= 0 then
         MC_Store.Begin_Write (Store, Content, Counter (Size), Writer, Status); Need;
         while Offset < Counter (Size) loop
            Clock;
            Read := MC_Posix.Pread (FD, Buffer'Address,
               Interfaces.C.size_t (Counter'Min (Counter (Buffer'Length), Counter (Size) - Offset)), Interfaces.C.long (Offset));
            if Read < 0 then
               if MC_Posix.Errno_Location.all /= MC_Posix.EINTR then Status := IO_Error; raise Interrupted; end if;
            elsif Read = 0 then Status := Stale; raise Interrupted;
            else
               MC_Store.Write_Chunk (Writer, Buffer (1 .. Natural (Read)), Status); Need;
               Offset := Offset + Counter (Read);
            end if;
         end loop;
         Clock; MC_Store.Finish_Write (Store, Writer, Status); Need;
      elsif Content /= Zero_Digest or else Size /= 0 then Status := Corrupt; raise Interrupted;
      end if;
      Clock;
      declare
         Raw : Bytes (1 .. Natural (Used)) with Import, Address => Meta;
      begin MC_Store.Put (Store, Raw, Meta_Hash, Status); Need; end;
      Status := Result (Check (Handle, Interfaces.C.unsigned_long_long (Deadline))); Need; Clock;
      Value.Handle := Handle; Handle := System.Null_Address;
      Value.Reservation := MC_Store.Native_Reservation (Store); Value.Meta := Meta_Hash;
      Value.Image := (if FD >= 0 then (Pkg_Conffile_Transition.Regular, Content)
                      else (Pkg_Conffile_Transition.Missing, Zero_Digest));
      Cleanup;
   exception
      when Interrupted => Cleanup; Clear (Value);
      when Storage_Error => Cleanup; Clear (Value); Status := Exhausted;
      when others => Cleanup; Clear (Value); Status := Indeterminate;
   end Capture;
end Pkg_Conffile_Snapshot;
