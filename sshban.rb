#!/usr/bin/ruby

####################
## Current to-do: 
## Need 3 total files
## SSHBAN.rb, BANFILE.dat, PREVIOUSBANS.dat
## Banfile = current, outstanding bans
## PreviousBans = all previous bans
## PrevBnas file will be used to make sure next ban isn't the same as last ban (for main)
## Unban method will only deal with the unbanning and deletion of bans in BANFILE
## Don't get these two methods and files mixed up, they remain separate with two roles

require 'time'
require 'optparse'
require 'fileutils'

$options = {:secsBetweenTries => 60, :banMinutes => 120, :debug => false}
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

end.parse!

def buildFails(amountLinesToRead)
  # Check auth.log for the latest authentication failures
  failHash = {}
  for a in IO.readlines("/var/log/auth.log")[-amountLinesToRead..-1]
    if (a.include?"Failed password for")
      
      # Index based on server name, get time of failure
      hostLocation = a.index(" vps ")
      dateTime = a[0..hostLocation]
      failTime = Time.parse(dateTime).strftime("%m/%d/%y %H:%M:%S")
      
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
    banList.push(eval(bans))
  end

  banFile.close()
  return banList
end

def appendBanFile(line)
  # Make sure the ban file exists
  unless (File.exist?"banfile.dat")
    FileUtils.touch("banfile.dat")
  end

  # Append the packaged ban string to the file
  banFile = File.open("banfile.dat", "a")
  banFile.write(line.to_s + "\n")
  banFile.close()
end

def rewriteBanFile(list)
  banFile = File.open("banfile.dat", "w")
  
  # Instead of writing full list, write each line by line
  unless (list.nil?)
    for ban in list
      banFile.write(ban.to_s)
    end
  else File.truncate("banfile.dat", 0)
  end
  banFile.close()
  puts("Rewrite finished")

end

# Get our failed attempts from auth.log and get previous ban list from file
$failList = buildFails(1000)
$banList = evalBanFile()

def main()
  # For every IP address in ["0.0.0.0"=>[0/0/0000 0:0:0, 0/0/0000 0:0:0]]
  for a in $failList.keys
    # Current IP address
    thisIP = a
    # Reverse the order of failure times, most recent at top
    thisList = $failList[a].reverse
    
    # Debug outputs
    if $options[:debug]
      puts(a) 
      puts("-------") 
    end  

    # For every failure time for this IP address 'a' 
    for b in thisList
      # Debug output
      puts(b) if $options[:debug]

      # Get the index number of the first failure time, and the next 2
      thisIndex = thisList.index(b)
      nextTime = thisList[thisIndex+1]
      nextTwoTimes = thisList[thisIndex+2]
  
      # ...unless it next failure time doesn't exist
      unless (nextTime.nil?)

       # puts(b.to_s + " minus " + nextTime.to_s)
        
        # If the time between the first two failures are less than set in arguments
        if (Time.parse(b) - Time.parse(nextTime) <= $options[:secsBetweenTries])

          # Unless there is no third failure
          unless (nextTwoTimes.nil?)

            # If the time between the second and third failures are less than set in arguments
            if (Time.parse(nextTime) - Time.parse(nextTwoTimes) <= $options[:secsBetweenTries])
              #puts(b.to_s + " " + nextTwoTimes.to_s + " = " + (Time.parse(b) - Time.parse(nextTwoTimes)).to_s)
              
              # Check the banfile to see if the IP already exists
              stopBan = false
              unless ($banList.nil?)
                for bans in $banList
                  if (bans.include? thisIP)
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
                appendBanFile(theBan)
           
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
              else puts("IP already banned")
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
  for bans in $banList
    puts("ban inspect")
    puts(bans.inspect)
    
    # Define for clarity
    banStart = bans[0]
    banIP = bans[1]
    banLastAttempt = bans[2]
    currentTime = Time.now.strftime("%m/%d/%y %H:%M:%S")

    # Time (minutes) between now and start of ban
    timeBetween = (Time.parse(currentTime) - Time.parse(banStart)) / 60.0
    
    # Debug
    puts(banIP) if $options[:debug]
    
    # If the time between now and ban start >= ban period, unban IP and delete from file
    if (timeBetween >= $options[:banMinutes])
      begin
        system('ufw delete deny from ' + banIP.to_s + ' to any port 22')
      rescue
        puts("UFW unban command failed")
      end

      puts("Deleting ban from ban file")
      $banList = $banList.delete($banList.index(bans))
      rewriteBanFile($banList)
    else 
      puts("stays banned for: " + ($options[:banMinutes] - timeBetween).to_s + " mins") if $options[:debug]
    end
  puts("banlist inspect")
  puts($banList.inspect)
  end
end

unbanCheck()
main()
