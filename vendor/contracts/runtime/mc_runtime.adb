-- SPDX-License-Identifier: MIT
with Interfaces.C; with System; with System.Storage_Elements;
package body MC_Runtime with SPARK_Mode => Off is
   use Interfaces.C; use type System.Address;
   function Sodium_Init return int with Import,Convention=>C,External_Name=>"sodium_init";
   function Signal(N : int; Handler : System.Address) return System.Address
     with Import,Convention=>C,External_Name=>"signal";
   function Umask(M : unsigned) return unsigned with Import,Convention=>C,External_Name=>"umask";
   function Prctl(Option : int; A,B,C,D : unsigned_long) return int
     with Import,Convention=>C,External_Name=>"prctl";
   procedure Initialize(Status : out Outcome) is
      Old : unsigned; H : System.Address;
      pragma Unreferenced(Old,H);
   begin
      Status:=IO_Error; Old:=Umask(8#077#);
      if Sodium_Init<0 then return; end if;
      -- SIG_IGN is the Linux/glibc pointer sentinel 1. Suppress dumpable secrets.
      H:=Signal(13,System'To_Address(1));
      if H=System.Storage_Elements.To_Address(System.Storage_Elements.Integer_Address'Last) then return; end if;
      -- MC_Command exclusively owns child reaping. Inherited SIG_IGN for SIGCHLD
      -- would auto-reap and allow PID reuse before process-group cleanup.
      -- Call once, before creating any children/native worker threads.
      H:=Signal(17,System.Null_Address);
      if H=System.Storage_Elements.To_Address(System.Storage_Elements.Integer_Address'Last) then return; end if;
      if Prctl(4,0,0,0,0)/=0 then return; end if;
      Status:=OK;
   end Initialize;
end MC_Runtime;
