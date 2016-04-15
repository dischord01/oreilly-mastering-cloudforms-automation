begin
  
  def get_current_group_rbac_array(user, rbac_array=[])
    unless user.current_group.filters.blank?
      user.current_group.filters['managed'].flatten.each do |filter|
        next unless /(?<category>\w*)\/(?<tag>\w*)$/i =~ filter
        rbac_array << {category=>tag}
      end
    end
    $evm.log(:info, "rbac filters: #{rbac_array}")
    rbac_array
  end
   
  def service_visible?(rbac_array, service)
    $evm.log(:info, "Evaluating Service #{service.name}")
    rbac_array.each do |rbac_hash|
      rbac_hash.each do |category, tag|
        if service.tagged_with?(category, tag)
          $evm.log(:info, "Service: #{service.name} is visible to this user")
          return true
        end
      end
    end
    false
  end

  user = $evm.root['user']
  rbac_array = get_current_group_rbac_array(user)
  values_hash      = {}
  visible_services = []
  
  $evm.vmdb(:service).find(:all).each do |service|
    if service['display']
      $evm.log(:info, "Found service: #{service.name}")
      if service_visible?(rbac_array, service)
        visible_services << service
      end
    end
  end
  if visible_services.length > 0
    if visible_services.length > 1
      values_hash['!'] = '-- select from list --'
    end
    visible_services.each do |service|
      values_hash[service.id] = service.name
    end
  else
    values_hash['!'] = 'No services are available'
  end

  list_values = {
      'sort_by'    => :description,
      'data_type'  => :string,
      'required'   => true,
      'values'     => values_hash
  }
  list_values.each { |key, value| $evm.object[key] = value }
  exit MIQ_OK
rescue => err
  $evm.log(:error, "[#{err}]\n#{err.backtrace.join("\n")}")
  exit MIQ_STOP
end

