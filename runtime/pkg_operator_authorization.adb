-- SPDX-License-Identifier: BSD-3-Clause
with Interfaces.C; with MC_Hex;
package body Pkg_Operator_Authorization with SPARK_Mode => Off is
   use type System.Address;
   function Convert (Code : Interfaces.C.int) return Outcome is
     (case Code is when 0 => OK, when 3 => Stale, when 4 => Conflict, when others => Denied);
   procedure Open (C : in out Session; Peer_FD : Integer; Plan : Digest;
      Request_ID : Identity; Deadline : Counter; Interactive : Boolean; Status : out Outcome) is
      function Start (Handle : in out System.Address; Peer_FD : Interfaces.C.int;
         Plan, Request_ID : System.Address; Deadline : Interfaces.C.unsigned_long_long;
         Interactive : Interfaces.C.int) return Interfaces.C.int
        with Import, Convention => C, External_Name => "nia_operator_open";
      P : aliased constant String := MC_Hex.Encode (Plan) & Character'Val (0);
      R : aliased constant String := MC_Hex.Encode (Request_ID) & Character'Val (0);
   begin
      Status := Conflict; if C.Handle /= System.Null_Address then return; end if;
      Status := Invalid_Input;
      if Peer_FD < 0 or else Plan = Zero_Digest or else Request_ID = Zero_Identity then return; end if;
      Status := Convert (Start (C.Handle, Interfaces.C.int (Peer_FD), P'Address, R'Address,
         Interfaces.C.unsigned_long_long (Deadline), Boolean'Pos (Interactive)));
   exception when others => Close (C); Status := Indeterminate;
   end Open;
   procedure Check (C : in out Session; Plan : Digest; Request_ID : Identity; Status : out Outcome) is
      function Current (Handle, Plan, Request_ID : System.Address) return Interfaces.C.int
        with Import, Convention => C, External_Name => "nia_operator_check";
      P : aliased constant String := MC_Hex.Encode (Plan) & Character'Val (0);
      R : aliased constant String := MC_Hex.Encode (Request_ID) & Character'Val (0);
   begin
      Status := Convert (Current (C.Handle, P'Address, R'Address));
   exception when others => Close (C); Status := Indeterminate;
   end Check;
   procedure Close (C : in out Session) is
      procedure Finish (Handle : in out System.Address)
        with Import, Convention => C, External_Name => "nia_operator_close";
   begin Finish (C.Handle); end Close;
   overriding procedure Finalize (C : in out Session) is
   begin Close (C); end Finalize;
end Pkg_Operator_Authorization;
