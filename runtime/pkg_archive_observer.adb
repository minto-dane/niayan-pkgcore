-- SPDX-License-Identifier: BSD-3-Clause
with Ada.Unchecked_Deallocation; with Interfaces.C; with System;
with MC_Authentic; with MC_Clock; with MC_FS; with MC_Hex; with MC_Posix; with MC_SHA256;
package body Pkg_Archive_Observer with SPARK_Mode => Off is
   use type Interfaces.C.unsigned;
   use type Word;
   type Buffer_Access is access Bytes;
   procedure Free is new Ada.Unchecked_Deallocation (Bytes, Buffer_Access);
   procedure Observe (Store : in out MC_Store.Store; Request_ID : Digest;
      Original, Control, InRelease, Index, Keyring : Digest;
      Index_Path, Deb_Path : String; Observer_UID : Word;
      Trusted : Pkg_Archive_Supply.Authority; Deadline : Counter;
      Receipt, Policy : out Digest; Status : out Outcome) is
      function Request (ID, Scope, Index_Name, Deb_Name : System.Address;
         UID : Interfaces.C.unsigned; Deadline : Interfaces.C.unsigned_long_long;
         Release_FD, Index_FD, Deb_FD : Interfaces.C.int;
         Wire, Policy, Policy_Size : System.Address) return Interfaces.C.int
        with Import, Convention => C, External_Name => "nia_archive_observe";
      ID : aliased constant String := MC_Hex.Encode (Request_ID) & Character'Val (0);
      Scope : aliased constant String := MC_Hex.Encode (Trusted.Scope) & Character'Val (0);
      Index_Name : aliased constant String := Index_Path & Character'Val (0);
      Deb_Name : aliased constant String := Deb_Path & Character'Val (0);
      Files : array (1 .. 5) of MC_FS.File;
      Hashes : constant array (1 .. 5) of Digest := (InRelease, Index, Original, Control, Keyring);
      Wire : Bytes (1 .. Pkg_Archive_Supply.Wire_Size) := (others => 0);
      Data : Buffer_Access := null;
      Size : aliased Interfaces.C.unsigned := 0;
      Code : Interfaces.C.int;
      Started, Boot, Before, Now : Counter;
      Saved_Receipt, Saved_Policy, Binding : Digest := Zero_Digest;
      Interrupted : exception;
      procedure Check is
      begin if Status /= OK then raise Interrupted; end if; end Check;
      procedure Clock is
      begin
         MC_Clock.Boottime_Milliseconds (Boot, Status); Check;
         if Boot >= Deadline or else Boot < Started then Status := Stale; raise Interrupted; end if;
      end Clock;
      procedure Cleanup is
      begin for F of Files loop MC_FS.Close (F); end loop; Free (Data); end Cleanup;
   begin
      Receipt := Zero_Digest; Policy := Zero_Digest; Status := Denied;
      if MC_Posix.Euid = 0 then return; end if;
      Status := Invalid_Input;
      if Request_ID = Zero_Digest or else Trusted.Scope = Zero_Digest or else Is_Zero (Trusted.Key)
        or else Observer_UID = 0 or else Observer_UID = Word (MC_Posix.Euid)
        or else Trusted.Minimum_Epoch not in 1 .. 2 ** 53 - 1
        or else Trusted.Maximum_Age not in 1 .. Pkg_Archive_Supply.Max_Lifetime
        or else (for some D of Hashes => D = Zero_Digest)
        or else Index_Path'Length not in 1 .. 4_096 or else Deb_Path'Length not in 1 .. 4_096
        or else (for some C of Index_Path => C = Character'Val (0))
        or else (for some C of Deb_Path => C = Character'Val (0))
        or else MC_Store.Native_Reservation (Store) < 0 or else Deadline = Counter'Last then return; end if;
      MC_Clock.Boottime_Milliseconds (Started, Status); Check;
      if Deadline <= Started or else Deadline - Started > 130_000 then Status := Stale; raise Interrupted; end if;
      MC_Clock.Realtime_Seconds (Before, Status); Check;
      for I in Files'Range loop
         Clock; MC_Store.Open_Object (Store, Hashes (I), Files (I), Status); Check;
      end loop;
      Clock;
      Data := new Bytes (1 .. Maximum_Policy);
      Code := Request (ID'Address, Scope'Address, Index_Name'Address, Deb_Name'Address,
         Interfaces.C.unsigned (Observer_UID), Interfaces.C.unsigned_long_long (Deadline),
         Interfaces.C.int (MC_FS.Native (Files (1))), Interfaces.C.int (MC_FS.Native (Files (2))),
         Interfaces.C.int (MC_FS.Native (Files (3))), Wire'Address, Data.all'Address, Size'Address);
      case Code is
         when 0 => Status := OK;
         when 1 => Status := Denied;
         when 3 => Status := Stale;
         when others => Status := Indeterminate;
      end case;
      Check; Clock;
      if Size not in 1 .. Interfaces.C.unsigned (Maximum_Policy) then Status := Corrupt; raise Interrupted; end if;
      if Wire (1 .. 8) /= Bytes'(78, 73, 65, 83, 85, 80, 48, 49)
        or else Wire (9 .. 40) /= Trusted.Scope or else Wire (73 .. 104) /= Original
        or else Wire (105 .. 136) /= Control or else Wire (137 .. 168) /= InRelease
        or else Wire (169 .. 200) /= Index or else Wire (201 .. 232) /= Keyring
        or else Wire (41 .. 72) /= MC_SHA256.Hash (Data (1 .. Natural (Size))) then
         Status := Denied; raise Interrupted;
      end if;
      MC_Authentic.Verify ("NiaOS/archive-supply/v1", Wire (1 .. 256), Wire (257 .. 320), Trusted.Key, Status); Check;
      Clock; MC_Store.Put (Store, Data (1 .. Natural (Size)), Saved_Policy, Status); Check;
      Clock; MC_Store.Put (Store, Wire, Saved_Receipt, Status); Check;
      MC_Clock.Realtime_Seconds (Now, Status); Check;
      if Now < Before then Status := Stale; raise Interrupted; end if;
      Pkg_Archive_Supply.Verify_Original (Store, Saved_Receipt, Original, Control, Trusted,
         Now, Deadline, Binding, Status); Check;
      Clock; Receipt := Binding; Policy := Saved_Policy; Cleanup;
   exception
      when Interrupted => Cleanup; Receipt := Zero_Digest; Policy := Zero_Digest;
      when Storage_Error => Cleanup; Receipt := Zero_Digest; Policy := Zero_Digest; Status := Exhausted;
      when others => Cleanup; Receipt := Zero_Digest; Policy := Zero_Digest; Status := Indeterminate;
   end Observe;
end Pkg_Archive_Observer;
