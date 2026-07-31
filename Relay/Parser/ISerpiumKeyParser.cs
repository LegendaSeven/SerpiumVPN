namespace SerpiumVPN.Relay.Parser;

public interface ISerpiumKeyParser
{
    bool CanParse(string key);
    SerpiumParseResult Parse(string key);
}
