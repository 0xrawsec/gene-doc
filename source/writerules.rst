*************
Writing Rules
*************

Gene rules have been designed to be straightforward to understand and to parse.
In order not to have to develop a custom rule parser, we have decided to use JSON
document as container. Then every rule, to work properly, has to follow a specific
format which is going to be described in this page.

Getting the format supported by the engine
==========================================

A starting point to understand the format of a rule is to use the ``gene`` command
line utility to get the format supported by your engine::

    gene -template

This command line should return a JSON document containing all the fields used
by your current version of ``gene``.

Rule Structure
==============

.. code-block:: JSON

  {
    "Name": "",
    "Tags": [],
    "Meta": {
      "EventIDs": [],
      "Channels": [],
      "Computers": [],
      "Traces": [],
      "Criticality": 0,
      "Disable": false
    },
    "Matches": [],
    "Condition": ""
  }

.. important::
  The fields present in the template shown above are the ones used by the engine.
  It means that **any** additional field will not impact the engine. This
  trick can be used to document the rule. It is a good practice to add information
  such as **Author**, **Comments** and eventual **Links** in the **Meta** section.



.. table:: Field Definition

  +------------+------------+----------------------------------------------------+
  | Field      | Type       | Description                                        |
  +============+============+====================================================+
  | Name       | string     | Name of the rule                                   |
  |            |            |                                                    |
  +------------+------------+----------------------------------------------------+
  | Tags       | []string   |  Contains a list of tags related to the rule. It   |
  |            |            |  can be used to group rules                        |
  |            |            |  according to their tag(s).                        |
  +------------+------------+----------------------------------------------------+
  | Meta       | dict       | Contains a bunch of information related the trigger|
  |            |            | of the rule. The information in there is used to   |
  |            |            | match against the "System" section of the Windows  |
  |            |            | events to speed up the match.                      |
  +------------+------------+----------------------------------------------------+
  | EventIDs   | []int      | List of Windows Event IDs the rule should match    |
  |            |            | against. If empty the rule will apply against any  |
  |            |            | Event ID of the ``Channels`` (c.f. see next)       |
  +------------+------------+----------------------------------------------------+
  | Channels   | []string   | List of channels the rule should apply on. If      |
  |            |            | empty, the rule will apply against any event of any|
  |            |            | channel.                                           |
  +------------+------------+----------------------------------------------------+
  | Computers  | []string   | List of computer names the rule should apply on.   |
  |            |            | If empty, the rule applies on all the computers.   |
  +------------+------------+----------------------------------------------------+
  | Traces     | []string   | List of traces used to trace other events related  |
  |            |            | to the rule. A rule can be used to generate        |
  |            |            | dynamic rules with information from the event which|
  |            |            | matched the rule. The syntax of each trace must    |
  |            |            | follow `Traces Format`_.                           |
  +------------+------------+----------------------------------------------------+
  |Criticality |0 < int < 10| The criticality level attributed to the events     |
  |            |            | matching the rule. If an event matches several     |
  |            |            | rules the criticality levels are added between them|
  |            |            | and will never go above 10.                        |
  +------------+------------+----------------------------------------------------+
  | Disable    | bool       | Boolean value used to disable the rule.            |
  +------------+------------+----------------------------------------------------+
  | Matches    | []string   | List of **Matches**, should follow the syntax of   |
  |            |            | `Matches Format`_                                  |
  +------------+------------+----------------------------------------------------+
  | Condition  | string     | String implementing the logic on the **Matches** to|
  |            |            | trigger the rule. The syntax should be compliant   |
  |            |            | with `Condition Format`_                           |
  +------------+------------+----------------------------------------------------+

.. important::
  The more precise **EventIDs** and **Channels** fields, the faster the rule is.
  Those information are mainly used to filter out irrelevant events.

Matches Format
--------------

A **Match** can be seen as an atomic check which is done on every Windows Event
(pre-filtered using **Meta** section of the rule) going through the engine. Every
match can be referenced once or more in the **Condition** to create complex
matching rule. Currently, the latest version of the engine supports two kinds of
**Matches**.

.. important::
  It is very important to remember that **Matches** only apply on the fields
  located under the ``EventData`` section of Windows Events.

Field Matches
^^^^^^^^^^^^^

A **Field Match** is basically an **equality** or a **regex** check done on a
given **field value**. This kind of **Match** brings flexibility to the engine since
anything can be matched through regular expression.

**Syntax:** ``$VAR_NAME: FIELD OPERATOR 'VALUE'``

.. table:: Field Match Symbols Definition

  +------------+----------------------------------------------------------------+
  | Symbols    | Description                                                    |
  +============+================================================================+
  | VAR_NAME   | Name of the variable use to access the result of the **Match** |
  |            | in the **Condition**, it must be preceded by a ``$``           |
  +------------+----------------------------------------------------------------+
  | FIELD      | Field to match with in ``EventData`` section of Windows Events |
  +------------+----------------------------------------------------------------+
  | OPERATOR   | Operator to use for the match:                                 |
  |            |  * ``=`` : equal operator                                      |
  |            |  * ``~=`` : regexp operator (tells to compile VALUE as a regex)|
  +------------+----------------------------------------------------------------+
  | VALUE      | Must be surrounded by **simple quotes** ``'``. This is the     |
  |            | **value/regex** to match against to make **$VAR_NAME = true**  |
  +------------+----------------------------------------------------------------+


Match Workflow::

            +-------+               +---------+
            | Event |               |  Match  |
            +-------+               +---------+
                |      +----------+      |
                +----> |  Engine  | <----+
                       +----------+
                             |
               +---------------------------+
               | Extracts value from FIELD |
               +---------------------------+
                             |
               +---------------------------+
               |   Does value match VALUE  |
               |   according to OPERATOR ? |
               +---------------------------+
                             |
                             ^
                      YES  /   \  NO
                          /     \
                         /       \
                        /         \
        +------------------+    +-------------------+
        | $VAR_NAME = true |    | $VAR_NAME = false |
        +------------------+    +-------------------+
                        \         /
                         \       /
                  +--------------------+
                  | $VAR_NAME value is |
                  |  used in condition |
                  +--------------------+


.. important::
  Any regular expression must follow `Go regexp syntax <https://golang.org/pkg/regexp/syntax/>`_.

Example:
""""""""

The following snippet shows a rule used to catch Windows Event log clearing attempts
using ``wevutil.exe``.

.. code-block:: JSON

  {
  "Name": "EventClearing",
  "Tags": ["PostExploit"],
  "Meta": {
    "EventIDs": [1],
    "Channels": ["Microsoft-Windows-Sysmon/Operational"],
    "Computers": [],
    "Criticality": 8,
    "Author": "@0xrawsec"
    },
  "Matches": [
    "$im: Image ~= '(?i:\\\\wevtutil\\.exe$)'",
    "$cmd: CommandLine ~= '(?i: cl | clear-log )'"
    ],
  "Condition": "$im and $cmd"
  }

.. warning::
  In order to match a single ``\`` Windows path separator, we need to use ``\\\\``
  when using ``=~`` and ``\\`` when using ``=`` operator

Container Matches
^^^^^^^^^^^^^^^^^

An **Container Match** is a little bit more advanced since it can be used to extract
a part of a **field value** and check it against a container. For
instance, with this kind of **Match**, we are able to extract a **domain** information
contained in Windows DNS-Client logs and check it against a blacklist. Although,
implementing this use case would be possible with **Field Matches**, it
would be much slower due to regex engine. In addition the rule would need to be updated
at every new entry to check, however with **Container Match** only the container
(a simple separate file) needs to be updated. The speed is provided by the
container which is implemented in a form of a set data structure.

**Syntax:** ``$VAR_NAME: extract('REGEXP', FIELD) in CONTAINER``

.. table:: Container Match Symbols Definition

  +------------+----------------------------------------------------------------+
  | Symbols    | Description                                                    |
  +============+================================================================+
  | VAR_NAME   | Name of the variable used to access the result of the **Match**|
  |            | in the **Condition**, it must be preceded by a ``$``           |
  +------------+----------------------------------------------------------------+
  | FIELD      | Field to extract from                                          |
  +------------+----------------------------------------------------------------+
  | REGEXP     | Regular expression used to extract a value from FIELD and check|
  |            | it against a **CONTAINER**. **REGEXP** must follow **named**   |
  |            | regexp syntax ``(?P<name>re)``                                 |
  +------------+----------------------------------------------------------------+
  | CONTAINER  | Container to use to check the extracted value                  |
  +------------+----------------------------------------------------------------+

.. important::
  * If a rule makes use of an **undefined container**, the rule will be disabled
    at runtime and a warning message will be printed.
  * A given container is shared across all the rules loaded into the engine
  * Any regular expression must follow `Go regexp syntax <https://golang.org/pkg/regexp/syntax/>`_.

Example:
""""""""

This rule shows an example of how to extract domains and sub-domains from Windows
DNS-Client logs and check it against a blacklist.

.. code-block:: JSON

  {
  "Name": "BlacklistedDomain",
  "Tags": ["DNS"],
  "Meta": {
    "EventIDs": [],
    "Channels": ["Microsoft-Windows-DNS-Client/Operational"],
    "Computers": [],
    "Criticality": 10,
    "Author": "@0xrawsec",
    "Comment": ""
    },
  "Matches": [
      "$domainBL: extract('(?P<dom>\\w+\\.\\w+$)',QueryName) in blacklist'",
      "$subdomainBL: extract('(?P<sub>\\w+\\.\\w+\\.\\w+$)',QueryName) in blacklist'",
      "$subsubdomainBL: extract('(?P<subsub>\\w+\\.\\w+\\.\\w+\\.\\w+$)',QueryName) in blacklist'"
    ],
  "Condition": "$domainBL or $subdomainBL or $subsubdomainBL"
  }

Traces Format
-------------

A trace is used to generate a new rule **on the fly** derived from both the rule
which triggered and the **Windows Event** which matched. This feature allows
the engine to do some **basic** correlation. The rule generated is very basic
and has a single match.

**Syntax:** ``EVENT_IDS:CHANNELS: NEW_FIELD OPERATOR EVT_VAL_FIELD``

.. table:: Trace Symbols Definition

  +---------------+----------------------------------------------------------------+
  | Symbols       | Description                                                    |
  +===============+================================================================+
  | EVENT_IDS     | Comma separated list of **Windows Event IDs** used to set      |
  |               | EventIDs field of the new rule. If empty, default is to        |
  |               | inherit from **the rule defining the trace**.                  |
  +---------------+----------------------------------------------------------------+
  | CHANNELS      | Comma separated list of **Windows Event Log Channels** used to |
  |               | set **Channels** field of the generated rule. If empty, default|
  |               | is to inherit from **the rule defining the trace**.            |
  +---------------+----------------------------------------------------------------+
  | NEW_FIELD     | **Field name** to use for the **single Match** of the generated|
  |               | rule.                                                          |
  +---------------+----------------------------------------------------------------+
  | OPERATOR      | Operator to use for the match:                                 |
  |               |  * ``=`` : equal operator                                      |
  |               |  * ``~=`` : regexp operator (tells to compile VALUE as a regex)|
  +---------------+----------------------------------------------------------------+
  | EVT_VAL_FIELD | Name of the field in the matching **Windows Event** to extract |
  |               | the value from and used as **VALUE** in the generated rule     |
  +---------------+----------------------------------------------------------------+

.. important ::
  Keywords ``any``, ``ANY`` or ``*`` can be used instead  of comma separated list
  in **EVENT_IDS** and **CHANNELS** to respectively apply trace on any Event ID
  and any Channel.

The concept behind the traces is maybe a little bit hard to get (and also to explain).
That is why, in the following snippet, I have tried to show what a generated rule
from a trace would look like.

.. code-block:: JSON

  {
    "Name": "GENERATED_NAME",
    "Tags": ["inherited from triggering rule"],
    "Meta": {
      "EventIDs": ["inherited from triggering rule OR set from trace"],
      "Channels": ["inherited from triggering rule OR set from trace"],
      "Computers": ["inherited from triggering rule"],
      "Traces": [
        "inherited from triggering rule"
      ],
      "Criticality": "inherited from triggering rule",
    },
    "Matches": [
      "$m: NEW_FIELD OPERATOR 'ValueOf(CUR_FIELD) extracted from Matching Event'",
    ],
    "Condition": "$m"
  }

.. warning::
  * Traces generation is not enabled by default by the engine, in order to enable
    it, use the ``-trace`` command line switch
  * When trace mode is enabled, many rules can be generated at runtime and the
    engine will by design become slower since **any Windows Event** matches
    **any** rule loaded.
  * If **X** number of traces is defined, **X** rules will be generated at runtime when
    **trace mode** is enabled and the rule matches a **Windows Event**

Example:
^^^^^^^^

The following rule will generate rules to trace **any Event ID** from channel
**Microsoft-Windows-Sysmon/Operational** where either the **ProcessGuid** or
**ParentProcessGuid** is equal to the **ProcessGuid** of the event which triggered the
rule.

.. code-block:: JSON

  {
    "Name": "MaliciousLsassAccess",
    "Tags": ["Mimikatz", "Credentials", "Lsass"],
    "Meta": {
      "EventIDs": [10],
      "Channels": ["Microsoft-Windows-Sysmon/Operational"],
      "Computers": [],
      "Traces": [
        "*::ProcessGuid = ProcessGuid",
        "*::ParentProcessGuid = ProcessGuid"
      ],
      "Criticality": 10,
      "Author": "0xrawsec"
    },
    "Matches": [
      "$ct: CallTrace ~= 'UNKNOWN'",
      "$lsass: TargetImage ~= '(?i:\\\\lsass\\.exe$)'"
    ],
    "Condition": "$lsass and $ct"
  }

Condition Format
----------------

A condition applies a logic to the different **Matches** defined in the rule.
If the result of the computation of the **Condition** is **true** the event is
considered as matching the rule.

.. table:: Allowed Symbols in Condition

  +---------+----------------------------------------------------------------+
  | Symbols | Description                                                    |
  +=========+================================================================+
  | ``$var``| Variable referencing a **Match**                               |
  +---------+----------------------------------------------------------------+
  | ``()``  | Used to group / prioritize some logical expressions            |
  +---------+----------------------------------------------------------------+
  | ``!``   | Negates a **Match** or a grouped expression                    |
  +---------+----------------------------------------------------------------+
  | ``AND`` | AND logical operator                                           |
  +---------+                                                                |
  | ``and`` |                                                                |
  +---------+                                                                |
  | ``&&``  |                                                                |
  +---------+----------------------------------------------------------------+
  | ``OR``  | OR logical operator                                            |
  +---------+                                                                |
  | ``or``  |                                                                |
  +---------+                                                                |
  | ``||``  |                                                                |
  +---------+----------------------------------------------------------------+

.. important::
  For every **Windows Event** tested against a rule the **Condition** is evaluated in real
  time **from left to right**. As a consequence, the order of the variables to
  check might have a small impact on the rule performances. For more efficiency
  always try to put the more restrictive ones first.


Example:
^^^^^^^^

The following rule is used to match suspicious explicit network logons, we can
see an example of an advanced condition.

.. code-block:: JSON

  {
  "Name": "ExplicitNetworkLogon",
  "Tags": ["Lateral", "Security"],
  "Meta": {
    "EventIDs": [4624],
    "Channels": ["Security"],
    "Computers": [],
    "Criticality": 5,
    "Author": "@0xrawsec"
    },
  "Matches": [
  	"$logt: LogonType = '3'",
  	"$user: TargetUserName = 'ANONYMOUS LOGON'",
  	"$iplh1: IpAddress = '-'",
  	"$iplh2: IpAddress = '127.0.0.1'",
  	"$enddol: TargetUserName ~= '\\$$'"
    ],
  "Condition": "$logt and !($user or $iplh1 or $iplh2 or $enddol)"
  }
