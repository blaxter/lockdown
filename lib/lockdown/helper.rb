module Lockdown
  module Helper
    def class_name_from_file(str)
      str.split("/").collect{|s| camelize(s) }.join("::")
    end

    # If str_sym is a Symbol (:users), return "Users"
    # If str_sym is a String ("Users"), return :users
    def convert_reference_name(str_sym)
      if str_sym.is_a?(Symbol)
        titleize(str_sym)
      else
        underscore(str_sym).tr(' ','_').to_sym
      end
    end

    def get_string(value)
      if value.respond_to?(:name)
        string_name(value.name)
      else
        string_name(value)
      end
    end

    def get_symbol(value)
      if value.respond_to?(:name)
        symbol_name(value.name)
      elsif value.is_a?(String)
        symbol_name(value)
      else
        value
      end
    end

    def camelize(str)
      str.to_s.gsub(/\/(.?)/) { "::" + $1.upcase }.gsub(/(^|_)(.)/) { $2.upcase }
    end

    def random_string(len = 10)
      chars = ("a".."z").to_a + ("A".."Z").to_a + ("0".."9").to_a
      Array.new(len){||chars[rand(chars.size)]}.join
    end

    def administrator_group_string
      string_name(administrator_group_symbol)
    end

    def administrator_group_symbol
      :administrators
    end

    def qualified_const_defined?(klass)
      if klass =~ /::/
        namespace, klass = klass.split("::")
        eval("#{namespace}.const_defined?(#{klass})") if const_defined?(namespace)
      else
        const_defined?(klass)
      end
    end

    def qualified_const_get(klass)
      if klass =~ /::/
        namespace, klass = klass.split("::")
        eval(namespace).const_get(klass)
      else
        const_get(klass)
      end
    end

    private

    def string_name(str_sym)
      str_sym.is_a?(Symbol) ? convert_reference_name(str_sym) : str_sym
    end

    def symbol_name(str_sym)
      str_sym.is_a?(String) ? convert_reference_name(str_sym) : str_sym
    end

    def titleize(str)
      humanize(underscore(str)).gsub(/\b([a-z])/) { $1.capitalize }
    end
    
    def humanize(str)
      str.to_s.gsub(/_id$/, "").gsub(/_/, " ").capitalize
    end

    def underscore(str)
      str.to_s.gsub(/::/, '/').
        gsub(/([A-Z]+)([A-Z][a-z])/,'\1_\2').
        gsub(/([a-z\d])([A-Z])/,'\1_\2').
        tr("-", "_").downcase
    end
  end
end
