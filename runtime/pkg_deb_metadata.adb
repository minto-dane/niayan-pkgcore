-- SPDX-License-Identifier: MIT
with Ada.Unchecked_Deallocation; with Interfaces.C;
with MC_Clock; with MC_Posix;
with Pkg_Deb_Container; with Pkg_Deb_Control;
package body Pkg_Deb_Metadata with SPARK_Mode => Off is
   use type Interfaces.C.unsigned;
   procedure Inspect (Store : in out MC_Store.Store; Original : Digest; Deadline : Counter;
                      Result : out Observation; Status : out Outcome) is
      Envelope : Pkg_Deb_Container.Envelope; Now : Counter; Used : Natural;
      type Buffer_Access is access Bytes;
      type Control_Access is access Pkg_Deb_Control.Inventory;
      type Observation_Access is access Observation;
      procedure Free is new Ada.Unchecked_Deallocation (Bytes, Buffer_Access);
      procedure Free is new Ada.Unchecked_Deallocation (Pkg_Deb_Control.Inventory, Control_Access);
      procedure Free is new Ada.Unchecked_Deallocation (Observation, Observation_Access);
      Raw : Buffer_Access; Control : Control_Access; Candidate : Observation_Access;
      procedure Done is
      begin Free (Raw); Free (Control); Free (Candidate); end Done;
      procedure Check_Time is
      begin
         MC_Clock.Boottime_Milliseconds (Now, Status);
         if Status = OK and then Now >= Deadline then Status := Stale; end if;
      end Check_Time;
   begin
      Result := (others => <>); Status := Denied;
      if MC_Posix.Euid = 0 then return; end if;
      Pkg_Deb_Container.Inspect (Store, Original, Deadline, Envelope, Status); if Status /= OK then return; end if;
      -- These bounded records can exceed a megabyte; do not stack them with the
      -- archive reader's own candidate and the caller's observation.
      Control := new Pkg_Deb_Control.Inventory;
      Pkg_Deb_Control.Stage (Store, Envelope, Deadline, Control.all, Status); if Status /= OK then Done; return; end if;
      Candidate := new Observation;
      Candidate.Original := Original; Candidate.Archive := Control.Archive;
      Candidate.Control := Control.Entries (Control.Control_Index).Content;
      Free (Control);
      Raw := new Bytes (1 .. Pkg_Deb_Fields.Max_Control);
      MC_Store.Read_Object (Store, Candidate.Control, Raw.all, Used, Status);
      if Status /= OK then Done; return; end if;
      Check_Time; if Status /= OK then Done; return; end if;
      Pkg_Deb_Fields.Parse (Raw (1 .. Used), Candidate.Fields, Status);
      if Status = OK then Pkg_Deb_Fields.Check_Identity (Raw (1 .. Used), Candidate.Fields, Candidate.Identity, Status); end if;
      Free (Raw); if Status /= OK then Done; return; end if;
      Check_Time; if Status = OK then Result := Candidate.all; end if;
      Done;
   exception
      when Storage_Error => Done; Result := (others => <>); Status := Exhausted;
      when others => Done; Result := (others => <>); Status := IO_Error;
   end Inspect;
end Pkg_Deb_Metadata;
