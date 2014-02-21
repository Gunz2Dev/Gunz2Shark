using System;
using System.Collections.Generic;

namespace Gunz2Shark
{
    [Serializable]
    class Parameter
    {
        public string Name { get; set; }
        public string Type { get; set; }
    }

    [Serializable]
    class Command
    {
        public string Desc { get; set; }
        public string Id { get; set; }
        public List<Parameter> Params { get; set; }

        public int GetOpcode()
        {
            return UInt16.Parse(Id, System.Globalization.NumberStyles.AllowHexSpecifier);
        }
    }
}
