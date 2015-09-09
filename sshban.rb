#!/usr/bin/ruby
require 'time'
require 'optparse'
require 'fileutils'

$options = {:secsBetweenTries => 60, :banMinutes => 120, :debug => false}
OptionParser.new do |opts|
  opts.banner = "Usage: sshban.rb [options]"
  opts.on('-t', '--tries seconds', 'Amount of seconds between failed tries') do |secs|
    $options[:secsBetweenTries] = secs.to_i;
  end
  opts.on('-d', '--debug bool', 'Enable debug mode') do |bools|
    $options[:debug] = bools;
  end

end.parse!

#secsBetweenTries = 60

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

#def evalBanFile()
#  banFile = File.open("banfile.dat", "r")
#  banList = eval(banFile.gets)
#  banFile.close()
#
#  puts(banList)
#end

def appendBanFile(line)
  unless (File.exist?"banfile.dat")
    FileUtils.touch("banfile.dat")
  end 

  banFile = File.open("banfile.dat", "a")
  banFile.write(line.to_s + "\n")
  banFile.close()
end


$failList = buildFails(1000)
#evalBanFile()

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

              # Create a package like this: [Current time, IP Address, Last failure attempt time]
              currentTime = Time.now.strftime("%m/%d/%y %H:%M:%S")
              theBan = [currentTime, thisIP, Time.parse(b).to_s]
              
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

            end
          end
        end
        #puts(Time.parse(b) - Time.parse(nextTime))
      end
    end
  end
end

main()
