-- SPDX-License-Identifier: MIT
with Interfaces.C; with System; with MC_Hex;
package body Pkg_Root_Preparation with SPARK_Mode => Off is
   procedure Request
     (Socket_Path : String; Generation, Root_Manifest, Archive, Worker : Digest;
      Stage : Identity; Size, Entries, Deadline : Counter;
      Archive_FD, Reservation_FD : Integer; Status : out Outcome) is
      function Send (Path, G, R, A, W, ID : System.Address;
         Size, Entries, Deadline : Interfaces.C.unsigned_long_long;
         Archive_FD, Reservation_FD : Interfaces.C.int) return Interfaces.C.int
        with Import, Convention => C, External_Name => "nia_root_prepare";
      Path : aliased constant String := Socket_Path & Character'Val (0);
      G : aliased constant String := MC_Hex.Encode (Generation) & Character'Val (0);
      R : aliased constant String := MC_Hex.Encode (Root_Manifest) & Character'Val (0);
      A : aliased constant String := MC_Hex.Encode (Archive) & Character'Val (0);
      W : aliased constant String := MC_Hex.Encode (Worker) & Character'Val (0);
      ID : aliased constant String := MC_Hex.Encode (Stage) & Character'Val (0);
      Result : Interfaces.C.int;
   begin
      Status := Invalid_Input;
      if Socket_Path'Length not in 1 .. 107 or else Socket_Path (Socket_Path'First) /= '/'
        or else (for some C of Socket_Path => C = Character'Val (0))
        or else Generation = Zero_Digest or else Root_Manifest = Zero_Digest
        or else Archive = Zero_Digest or else Worker = Zero_Digest or else Stage = Zero_Identity
        or else Archive_FD < 0 or else Reservation_FD < 0 then return; end if;
      Result := Send (Path'Address, G'Address, R'Address, A'Address, W'Address, ID'Address,
         Interfaces.C.unsigned_long_long (Size), Interfaces.C.unsigned_long_long (Entries),
         Interfaces.C.unsigned_long_long (Deadline), Interfaces.C.int (Archive_FD), Interfaces.C.int (Reservation_FD));
      case Result is
         when 0 => Status := OK;
         when 1 => Status := Denied;
         when 3 => Status := Stale;
         when others => Status := Indeterminate;
      end case;
   exception when others => Status := Indeterminate;
   end Request;
end Pkg_Root_Preparation;
