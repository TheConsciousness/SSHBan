#!/usr/bin/ruby

####################
## Troubleshooting:
## When auth.log resets, you will get a nil error
## Because there aren't enough lines to read

## TODO:
## Get lines in auth.log and then set buildFails(#lines)

require 'time'
require 'date'
require 'optparse'
require 'fileutils'
require 'json'

$options = {:secsBetweenTries => 60, :banMinutes => 120, :debug => false, :refSeconds => 10}
OptionParser.new do |opts|
  opts.banner = "Usage: sshban.rb [options]"
  opts.on('-b', '--between seconds', 'Amount of seconds between failed tries') do |secs|
    $options[:secsBetweenTries] = secs.to_i;
  end
  opts.on('-d', '--debug bool', 'Enable debug mode') do |bools|
    $options[:debug] = bools;
  end
  opts.on('-t', '--time minutes', 'Amount of minutes to ban IP') do |mins|
    $options[:banMinutes] = mins.to_i;
  end
  opts.on('-r', '--refresh seconds', 'Amount of seconds to check for new attempts') do |rsecs|
    $options[:refSeconds] = rsecs.to_i;
  end

end.parse!

def buildFails(amountLinesToRead)
  # Check auth.log for the latest authentication failures
  failHash = {}
  for a in IO.readlines("/var/log/auth.log")[-amountLinesToRead..-1]
    if (a.include?"Failed password for")
      
      # Index based on server name, get time of failure
      hostLocation = a.index(" vps ")
      dateTime = a[0..hostLocation]
      failTime = DateTime.parse(dateTime).strftime("%m/%d/%y %H:%M:%S")
      
      # Index based on keywords, get IP Address
      fromLocation = a.index(" from ")
      portLocation = a.index(" port ")
      ipAddress = a[fromLocation..portLocation].sub("from ", "").sub(" p", "").delete(" ")

      # If the IP is already inside the IP list, push failure time to list, else set first time
      if (failHash.member?(ipAddress))
        failHash[ipAddress].push(failTime)
      else
        failHash[ipAddress] = [failTime]
      end
    end
  end
  return failHash
end

def evalBanFile()
  # Make sure the ban file exists
  unless (File.exist?"banfile.dat")
    FileUtils.touch("banfile.dat")
  end

  banFile = File.open("banfile.dat", "r")
  banList = []
  
  # For every ban line in file, evaluate it and put it into larger list
  for bans in banFile.readlines.each
    #puts(bans.split(",").inspect)
    #puts((JSON.parse bans).inspect)
    #puts("~~~~~~~~")
    #banList.push(eval(bans))

    # Eval is not safe, use JSON.parse to convert string to array
    # http://stackoverflow.com/questions/4477127/ruby-parsing-a-string-representation-of-nested-arrays-into-an-array
    banList.push(JSON.parse bans)
  end

  banFile.close()
  return banList
end

def evalPreviousBanFile()
  # Make sure the ban file exists
  unless (File.exist?"previousbans.dat")
    FileUtils.touch("previousbans.dat")
  end

  banFile = File.open("previousbans.dat", "r")
  banList = []

  # For every ban line in file, evaluate it and put it into larger list
  for bans in banFile.readlines.each
    banList.push(eval(bans))
  end

  banFile.close()
  return banList
end

def appendBanFile(file, line)
  # Make sure the ban file exists
  unless (File.exist?file)
    FileUtils.touch(file)
  end

  # Append the packaged ban string to the file
  banFile = File.open(file, "a")
  banFile.puts(line.to_s)
  banFile.close()
end

def rewriteBanFile(file, list)
  banFile = File.open(file, "w")
  
  # Instead of writing full list, write each line by line
  unless (list.nil?)
    for ban in list
      banFile.puts(ban.to_s)
    end
  else File.truncate(file, 0)
  end
  banFile.close()
  puts("Rewrite finished")

end

# Get our failed attempts from auth.log and get previous ban list from file
#$failList = buildFails(2000)
#$banList = evalBanFile()
#$previousBanList = evalPreviousBanFile()

def main()

  # Get the amount of lines in /var/log/auth.log
  numLines = %x[wc -l /var/log/auth.log].split(' ')
  puts("Number of auth.log lines: " + numLines[0].to_s) if $options[:debug]

  # Define our files
  $failList = buildFails(numLines[0].to_i - 1)
  $banList = evalBanFile()
  $previousBanList = evalPreviousBanFile()

  puts("Looping through auth.log failed attempts")

  # For every IP address in ["0.0.0.0"=>[0/0/0000 0:0:0, 0/0/0000 0:0:0]]
  for a in $failList.keys
    # Current IP address
    thisIP = a
    # Reverse the order of failure times, most recent at top
    thisList = $failList[a].reverse
    
    # Debug outputs
    if $options[:debug]
      puts("\nIP: " + a.to_s + " Time: " + $failList[a].to_s) 
      puts("--") 
    end  

    # For every failure time for this IP address 'a' 
    for b in thisList

      # Show time of failure
      puts(b) if $options[:debug]

      # Get the index number of the first failure time, and the next 2
      thisIndex = thisList.index(b)
      nextTime = thisList[thisIndex+1]
      nextTwoTimes = thisList[thisIndex+2]
  
      # ...unless it next failure time doesn't exist
      unless (nextTime.nil?)

        timeBetween = (DateTime.strptime(b, "%m/%d/%y %H:%M:%S").to_time - DateTime.strptime(nextTime, "%m/%d/%y %H:%M:%S").to_time)

        # Show seconds between output times
        #puts(DateTime.strptime(b, "%m/%d/%y %H:%M:%S").to_time - DateTime.strptime(nextTime, "%m/%d/%y %H:%M:%S").to_time, "secs ^ between V") if $options[:debug]
        puts(timeBetween.to_s + " secs between ^v") if $options[:debug]        

        # If the time between the first two failures are less than set in arguments
        if (DateTime.strptime(b, "%m/%d/%y %H:%M:%S").to_time - DateTime.strptime(nextTime, "%m/%d/%y %H:%M:%S").to_time <= $options[:secsBetweenTries])
          
          # Unless there is no third failure
          unless (nextTwoTimes.nil?)

            # If the time between the second and third failures are less than set in arguments
            if (DateTime.strptime(nextTime, "%m/%d/%y %H:%M:%S").to_time - DateTime.strptime(nextTwoTimes, "%m/%d/%y %H:%M:%S").to_time <= $options[:secsBetweenTries])

              #puts(b.to_s + " " + nextTwoTimes.to_s + " = " + (Time.parse(b) - Time.parse(nextTwoTimes)).to_s)

              # Check the ban files to see if the records already exists
              stopBan = false
              unless ($banList.nil?)
                for bans in $banList
                  if (bans.include? thisIP)
		    currentTime = Time.now.strftime("%m/%d/%y %H:%M:%S")
                    puts(currentTime + ": Ban currently in place, skipping.")
                    stopBan = true
                    break
                  end
                end
              end

              unless ($previousBanList.nil?)
                for preBans in $previousBanList
                  if (preBans.include? b)
                    # If preBans include (b = last failure attempt)
		    currentTime = Time.now.strftime("%m/%d/%y %H:%M:%S")
                    puts(currentTime + ": Previous ban found, skipping.")
                    stopBan = true
                    break
                  end
                end
              end

              # Unless the IP wasn't already banned, ban it
              unless (stopBan)

                # Create a package like this: [Current time, IP Address, Last failure attempt time]
                currentTime = Time.now.strftime("%m/%d/%y %H:%M:%S")
                theBan = [currentTime, thisIP, b]
              
                # ...and write the package to the file
                appendBanFile("banfile.dat", theBan)
                appendBanFile("previousbans.dat", theBan)
           
                # Raise the banhammer
                begin
                  system('ufw insert 1 deny from ' + thisIP.to_s + ' to any port 22')
                rescue
                  puts("UFW ban command failed.")
                end

                #ufw insert 1 deny from <ip> to any port 22
                #ufw delete deny from <ip> to any port 22

                # Prevent duplicate IPs being logged
                break
              else
		currentTime = Time.now.strftime("%m/%d/%y %H:%M:%S") 
		puts(currentTime + ": IP already banned")
              end

            end
          end
        end
        #puts(Time.parse(b) - Time.parse(nextTime))
      end
    end
  end
end

def unbanCheck()
  $banList = evalBanFile()
  
  puts("----- Running UnbanCheck -----") if $options[:debug]
  puts("----- BANLIST (currently banned)----") if $options[:debug]
  puts($banList.inspect) if $options[:debug]

  # Placeholder banlist for unexpired bans
  placeholder = []
  
  for bans in $banList
    
    puts("----- BANLIST loop, single ban: -----") if $options[:debug]
    puts(bans.inspect) if $options[:debug]
    
    # Define for clarity
    banStart = bans[0]
    banIP = bans[1]
    banLastAttempt = bans[2]
    currentTime = Time.now.strftime("%m/%d/%y %H:%M:%S")

    # Time (minutes) between now and start of ban
    timeBetween = (DateTime.strptime(currentTime, "%m/%d/%y %H:%M:%S").to_time - DateTime.strptime(banStart, "%m/%d/%y %H:%M:%S").to_time) / 60.0
    
    # If the time between now and ban start >= ban period, unban IP and delete from file
    if (timeBetween >= $options[:banMinutes])
      # This method only returns true, no try/catch works
      system('ufw delete deny from ' + banIP.to_s + ' to any port 22')  

      #$banList = $banList.delete($banList.index(bans))
      #rewriteBanFile("banfile.dat", $banList)
    else 
      puts("stays banned for: " + ($options[:banMinutes] - timeBetween).to_s + " mins") if $options[:debug]
      placeholder.push(bans)
    end

  end

  rewriteBanFile("banfile.dat", placeholder)
  $banList = placeholder
  puts($banList.inspect)
end

def repeat()
  while true
    main()
    unbanCheck()
    #main()
    puts("Sleeping") if $options[:debug]    
    sleep($options[:refSeconds])
  end
end

begin
  repeat()
rescue Exception => e
  `mail -s "SSHBan" 7656020229@txt.att.net<<EOM
The process has failed.`
  raise e
end



# Error Warning
#`mail -s "SSHBan" 7656020229@txt.att.net<<EOM
#The process has failed.`
