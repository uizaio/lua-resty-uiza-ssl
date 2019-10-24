
-- Parse the time strings (format: '2019-11-25T14:07:39Z') to os.time
return function(time_str)
    if time_str then
		local year, month, day, hour, min, sec, tzd;
		year, month, day, hour, min, sec, tzd = time_str:match("^(%d%d%d%d)-?(%d%d)-?(%d%d)T(%d%d):(%d%d):(%d%d)%.?%d*([Z+%-].*)$");
		if year then
			local time_offset = os.difftime(os.time(os.date("*t")), os.time(os.date("!*t"))); -- to deal with local timezone
			local tzd_offset = 0;
			if tzd ~= "" and tzd ~= "Z" then
				local sign, h, m = tzd:match("([+%-])(%d%d):?(%d*)");
				if not sign then return; end
				if #m ~= 2 then m = "0"; end
				h, m = tonumber(h), tonumber(m);
				tzd_offset = h * 60 * 60 + m * 60;
				if sign == "-" then tzd_offset = -tzd_offset; end
			end
			sec = (sec + time_offset) - tzd_offset;
			return os.time({year=year, month=month, day=day, hour=hour, min=min, sec=sec, isdst=false});
		end
	end
end
