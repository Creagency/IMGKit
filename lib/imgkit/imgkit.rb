class IMGKit
  KNOWN_FORMATS = [:jpg, :jpeg, :png]

  class NoExecutableError < StandardError
    def initialize
      msg  = "No wkhtmltoimage executable found at #{IMGKit.configuration.wkhtmltoimage}\n"
      msg << ">> Install wkhtmltoimage by hand or try running `imgkit --install-wkhtmltoimage`"
      super(msg)
    end
  end

  class ImproperSourceError < StandardError
    def initialize(msg)
      super("Improper Source: #{msg}")
    end
  end

  class CommandFailedError < RuntimeError
    attr_reader :command, :stderr
    def initialize(command, stderr)
      @command = command
      @stderr  = stderr
      super("Command failed: #{command}: #{stderr}")
    end
  end

  class UnknownFormatError < StandardError
    def initialize(format)
      super("Unknown Format: #{format}")
    end
  end

  attr_accessor :source, :stylesheets, :javascripts
  attr_reader :options

  def initialize(url_file_or_html, options = {})
    @source = Source.new(url_file_or_html)

    @stylesheets = []
    @javascripts = []

    @options = IMGKit.configuration.default_options.merge(options)
    @options.merge! find_options_in_meta(url_file_or_html) unless source.url?

    raise NoExecutableError.new unless File.exists?(IMGKit.configuration.wkhtmltoimage)
  end

  def command(output_file = nil)
    args = [executable]
    args += normalize_options(@options).to_a.flatten.compact

    if @source.html?
      args << '-' # Get HTML from stdin
    else
      args << @source.to_s
    end

    if output_file
      args << output_file.to_s
    else
      args << '-' # Read IMG from stdout
    end

    args
  end

  def executable
    default = IMGKit.configuration.wkhtmltoimage
    return default if default !~ /^\// # its not a path, so nothing we can do
    if File.exist?(default)
      default
    else
      default.split('/').last
    end
  end

  #if Open3.respond_to? :capture3
  #  def capture3(*opts)
  #    Open3.capture3(*opts)
  #  end
  #else
    # Lifted from ruby 1.9.2-p290 sources for ruby 1.8 compatibility
    # and modified to work on 1.8
    def capture3(*cmd, &block)
      if Hash === cmd.last
        opts = cmd.pop.dup
      else
        opts = {}
      end

      stdin_data = opts.delete(:stdin_data) || ''
      binmode = opts.delete(:binmode)
      out_value = ""
      err_value = ""
      buf = ""
      Open3.popen3(*cmd) {|i, out, err|
        still_open = [out,err]
        if binmode
          i.binmode
          out.binmode
          err.binmode
        end
        
        i.write stdin_data
        i.close
        while not still_open.empty?
          begin
            Rails.logger.info("still_open contains #{still_open.size}")
            fhs = select(still_open,nil,nil,1) # wait for data available in the pipes
            if fhs.nil?
              Rails.logger.info("=========> IO.Select timed out before threads ready: out: [closed?=#{out.closed?} eof?=#{out.eof?}] err: [closed?=#{err.closed?} eof?=#{err.eof?}]")
            else
              s = "fhs contains #{fhs.size}"
              fhs.each_with_index do |fh, ij|
                s = "#{s} [#{ij}:#{fh}]"             
              end
              Rails.logger.info(s)
              # fhs[0] is an array that contains filehandlers we can read from
              if fhs[0].include?(out)
                begin
                  out.read_nonblock(2048, buf) 
                  out_value << buf unless buf.nil?
                rescue EOFError  # If we have read everything from the pipe
                  out.close
                  Rails.logger.info("Closed OUT")
                  still_open.delete_if {|so| so==out}
                  out = nil
                rescue => e
                  Rails.logger.error("=========>    OUT block error: #{e}")
                end
              end
              if fhs[0].include? err
                begin
                  err.read_nonblock(2048, buf)
                  err_value << buf unless buf.nil?
                rescue EOFError  # If we have read everything from the pipe
                  err.close
                  Rails.logger.info("Closed ERR")
                  still_open.delete_if {|se| se==err}
                  err = nil
                rescue => e
                  Rails.logger.error("=========>    ERR block error: #{e}")
                end
              end
            end
          rescue => e
            Rails.logger.error("=========>    SELECT block error: #{e}")
            break
          end
        end
      }
      [out_value, err_value]
    #end
  end

  def to_img(format = nil, path = nil)
    #begin
 #     Rails.logger.info("<IMGKit>")
      append_stylesheets
      append_javascripts
      set_format(format)
  
      opts = @source.html? ? {:stdin_data => @source.to_s} : {}
      Rails.logger.info((command(path) + [opts]).join(" "))
      result, status = Open3.capture2(*(command(path) + [opts]))
      result.force_encoding("ASCII-8BIT") if result.respond_to? :force_encoding
      #Rails.logger.error("stderr: #{stderr}") unless stderr.nil?
      #Rails.logger.info("result nil?: #{result.nil?}")
 #     Rails.logger.info("result length: #{result.length}") unless result.nil?
      Rails.logger.info("status: #{status}")
 
      raise CommandFailedError.new(command.join(' '), stderr) if path.nil? and result.size == 0
    #rescue => e
    #  Rails.logger.error("IMGKit error: #{e.message}")
    #end
#    Rails.logger.info("</IMGKit>")
    result
  end

  def to_file(path)
    format = File.extname(path).gsub(/^\./,'').to_sym
    self.to_img(format, path)
    File.new(path)
  end

  def method_missing(name, *args, &block)
    if(m = name.to_s.match(/^to_(\w+)/))
      self.send(:to_img, m[1].to_sym)
    else
      super
    end
  end

  protected

    def find_options_in_meta(body)
      imgkit_meta_tags(body).inject({}) do |found, tag|
        name = tag.attributes["name"].sub(/^#{IMGKit.configuration.meta_tag_prefix}/, '').to_sym
        found.merge(name => tag.attributes["content"])
      end
    end

    def imgkit_meta_tags(body)
      require 'rexml/document'
      xml_body = REXML::Document.new(body)
      found = []
      xml_body.elements.each("html/head/meta") do |tag|
        found << tag if tag.attributes['name'].to_s =~ /^#{IMGKit.configuration.meta_tag_prefix}/
      end
      found
    rescue # rexml random crash on invalid xml
      []
    end

    def style_tag_for(stylesheet)
      "<style>#{stylesheet.respond_to?(:read) ? stylesheet.read : File.read(stylesheet)}</style>"
    end

    def script_tag_for(javascript)
      if javascript.respond_to?(:read)
        "<script>#{javascript.read}</script>"
      else
        "<script src=\"#{javascript}\" type=\"text/javascript\"></script>"
      end
    end

    def append_stylesheets
      raise ImproperSourceError.new('Stylesheets may only be added to an HTML source') if stylesheets.any? && !@source.html?

      stylesheets.each do |stylesheet|
        if @source.to_s.match(/<\/head>/)
          @source.to_s.gsub!(/(<\/head>)/, style_tag_for(stylesheet)+'\1')
        else
          @source.to_s.insert(0, style_tag_for(stylesheet))
        end
      end
    end

    def append_javascripts
      raise ImproperSourceError.new('Javascripts may only be added to an HTML source') if javascripts.any? && !@source.html?

      javascripts.each do |javascript|
        if @source.to_s.match(/<\/head>/)
          @source.to_s.gsub!(/(<\/head>)/, script_tag_for(javascript)+'\1')
        else
          @source.to_s.insert(0, script_tag_for(javascript))
        end
      end
    end

    def normalize_options(options)
      normalized_options = {}

      options.each do |key, value|
        next if !value
        normalized_key = "--#{normalize_arg key}"
        normalized_options[normalized_key] = normalize_value(value)
      end
      normalized_options
    end

    def normalize_arg(arg)
      arg.to_s.downcase.gsub(/[^a-z0-9]/,'-')
    end

    def normalize_value(value)
      case value
      when TrueClass
        nil
      when Array
        value
      else
        value.to_s
      end
    end

    def set_format(format)
      format = IMGKit.configuration.default_format unless format
      @options.merge!(:format => format.to_s) unless @options[:format]
      raise UnknownFormatError.new(format) unless KNOWN_FORMATS.include?(@options[:format].to_sym)
    end
end
