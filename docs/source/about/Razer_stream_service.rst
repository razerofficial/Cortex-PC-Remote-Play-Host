Razer Stream Service Mod
========================
Razer will work as clone of Sunshine project. But to work with Razer prodoct, some details needs some modifications.


Added Web APIs
------------------
The table lists the new Web APIs for Razer product.
Use like https://localhost:{portNumber}/api/[APINAME]

.. table::
   :widths: auto

   ================        ======   ===================================
   API Name                Method    Description
   ================        ======   ===================================
   resetConfig             POST     Reset All config
   shutdown                POST     Terminate Host exe
   tokens                  POST     Save pair token info
   multiApps               POST     Add multiple application list
   razeridPair             GET      Retrieve current host state
   razeridPair             POST     save Razer ID pairing config
   agreeRazeridPair        POST     agree Razer ID pairing when Manual
   apps/close              POST     Sunshine origin API
   ================        ======   ===================================

resetConfig
^^^^^^^^^^^^^^^^^^^
**Description**
   reset all the configuration.

shutdown
^^^^^^^^^^^^^^^^^^^
**Description**
   shutdown the host application gracefully.

tokens
^^^^^^^^^^^^^^^^^^^
**Description**
   save Razer pair token. This mehtod should be called at the beginning of the host launching.
**Structure**
   .. code-block:: text
      {    
         "RazerPairToken": "C9D64E8AD509410684AFD257325122B9"
      }

multiApps
^^^^^^^^^^^^^^^^^^^
**Description**
   Add multiple applications in one time.
.. table::
   :widths: auto

   ===========   ===============================
   Key           Name
   ===========   ===============================
   name          Game display game
   GUID          unique ID of the game 
   image_path    local image path, could be null
   launch_param  launch parameter, could be null
   launch_type   launch type, for UWP game 
   ===========   ===============================

**Structure**
   .. code-block:: text
      {    
    "apps": [
        {
            "name": "Paladins",
            "guid": "",
            "custom_image_path": "https:\/\/deals-assets-cdn.razerzone.com\/game_covers\/0084aecb-1595-a6f7-8c2c-1ab56583957e.webp",
            "cmd": "steam:\/\/rungameid\/444090",
            "launch_type": "other"
        },
        {
            "name": "banana",
            "GUID": "6a7a85eb-c4eb-bc23-6ade-fbb996de4ed4",
            "custom_image_path": "https:\/\/deals-assets-cdn.razerzone.com\/game_covers\/6a7a85eb-c4eb-bc23-6ade-fbb996de4ed4.webp",
            "cmd": "steam:\/\/rungameid\/2923300",
            "launch_type": "other"
        },
        {
            "name": "uwp game",
            "GUID": "6a7a85eb-c4eb-bc23-3ade-cdbf996de4ed4",
            "custom_image_path": "https:\/\/deals-assets-cdn.razerzone.com\/game_covers\/6a7a85eb-c4eb-bc23-6ade-fbb996de4ed4.webp",
            "cmd": "steam:\/\/rungameid\/2923300",
            "launch_type": "uwp"
        },
        {
            "name": "TANK",
            "guid": "59d58134-7eeb-441e-7e31-084d3d08b91e",
            "custom_image_path": "https:\/\/deals-assets-cdn.razerzone.com\/game_covers\/59d58134-7eeb-441e-7e31-084d3d08b91e.webp",
            "cmd": "E:\\Tanks_Tutorial\\tabk.exe ",
            "launch_type": "other"
        }
    ]
   }

razeridPair
^^^^^^^^^^^^
**Description**
Enable or disable Razer ID paring.There are they state  Manual/Automatic/Disable

**GET Structure**
   .. code-block:: text
   {
      "status": "true",
      "RazerIdPairing": "Automatic"
   }

**POST Structure**
.. code-block:: text
   {
      "RazerIdPairing" : "Disable"
   }

agreeRazeridPair
^^^^^^^^^^^^^^^^
**Description**
when razeridPair config is set to Manual, client connecting needs a agreement event
**POST Structure**
.. code-block:: text
   {
      "agreeRazeridPair" : "true"
   }

apps/close
^^^^^^^^^^
**Description**
To disconnet the streaming from host, This is sunshine orginal API, it was Force Close in web UI.
**POST Structure**
.. code-block:: text
   {
   }